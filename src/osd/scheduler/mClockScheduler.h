// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2016 Red Hat Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */


#pragma once

#include <functional>
#include <ostream>
#include <map>
#include <vector>

#include "boost/variant.hpp"

#include "dmclock/src/dmclock_server.h"

#include "osd/scheduler/OpScheduler.h"
#include "common/config.h"
#include "common/ceph_context.h"
#include "common/mClockPriorityQueue.h"
#include "osd/scheduler/OpSchedulerItem.h"


namespace ceph::osd::scheduler {

constexpr double default_min = 0.0;
constexpr double default_max = std::numeric_limits<double>::is_iec559 ?
  std::numeric_limits<double>::infinity() :
  std::numeric_limits<double>::max();

/**
 * client_profile_id_t
 *
 * client_id - global id (client.####) for client QoS
 * profile_id - id generated by client's QoS profile
 *
 * Currently (Reef and below), both members are set to
 * 0 which ensures that all external clients share the
 * mClock profile allocated reservation and limit
 * bandwidth.
 *
 * Note: Post Reef, both members will be set to non-zero
 * values when the distributed feature of the mClock
 * algorithm is utilized.
 */
struct client_profile_id_t {
  uint64_t client_id = 0;
  uint64_t profile_id = 0;

  client_profile_id_t(uint64_t _client_id, uint64_t _profile_id) :
    client_id(_client_id),
    profile_id(_profile_id) {}

  client_profile_id_t() = default;

  auto operator<=>(const client_profile_id_t&) const = default;
  friend std::ostream& operator<<(std::ostream& out,
                                  const client_profile_id_t& client_profile) {
    out << " client_id: " << client_profile.client_id
        << " profile_id: " << client_profile.profile_id;
    return out;
  }
};

struct scheduler_id_t {
  op_scheduler_class class_id;
  client_profile_id_t client_profile_id;

  auto operator<=>(const scheduler_id_t&) const = default;
  friend std::ostream& operator<<(std::ostream& out,
                                  const scheduler_id_t& sched_id) {
    out << "{ class_id: " << sched_id.class_id
        << sched_id.client_profile_id;
    return out << " }";
  }
};

/**
 * Scheduler implementation based on mclock.
 *
 * TODO: explain configs
 */
class mClockScheduler : public OpScheduler, md_config_obs_t {

  CephContext *cct;
  const int whoami;
  const uint32_t num_op_shard_threads;
  const int shard_id;
  const bool is_rotational;
  MonClient *monc;

  /**
   * osd_bandwidth_cost_per_io
   *
   * mClock expects all queued items to have a uniform expression of
   * "cost".  However, IO devices generally have quite different capacity
   * for sequential IO vs small random IO.  This implementation handles this
   * by expressing all costs as a number of sequential bytes written adding
   * additional cost for each random IO equal to osd_bandwidth_cost_per_io.
   *
   * Thus, an IO operation requiring a total of <size> bytes to be written
   * accross <iops> different locations will have a cost of
   * <size> + (osd_bandwidth_cost_per_io * <iops>) bytes.
   *
   * Set in set_osd_capacity_params_from_config in the constructor and upon
   * config change.
   *
   * Has units bytes/io.
   */
  double osd_bandwidth_cost_per_io;

  /**
   * osd_bandwidth_capacity_per_shard_thread
   *
   * mClock expects reservation and limit paramters to be expressed in units
   * of cost/second -- which means bytes/second for this implementation.
   *
   * Rather than expecting users to compute appropriate limit and reservation
   * values for each class of OSDs in their cluster, we instead express
   * reservation and limit paramaters as ratios of the OSD's maxmimum capacity.
   * osd_bandwidth_capacity_per_shard_thread is that capacity divided by the
   * number of op shard threads. This parameter factors in the number of
   * threads per OSD shard since there could be more than one worker thread
   * configured. Therefore, the capacity per shard is actually the capacity
   * per OSD op shard thread.
   *
   * Set in set_osd_capacity_params_from_config in the constructor and upon
   * config change.
   *
   * This value gets passed to ClientRegistry::update_from_config in order
   * to resolve the full reservaiton and limit parameters for mclock from
   * the configured ratios.
   *
   * Has units bytes/second.
   */
  double osd_bandwidth_capacity_per_shard_thread;

  class ClientRegistry {
    std::array<
      crimson::dmclock::ClientInfo,
      static_cast<size_t>(op_scheduler_class::immediate)
    > internal_client_infos = {
      // Placeholder, gets replaced with configured values
      crimson::dmclock::ClientInfo(1, 1, 1),
      crimson::dmclock::ClientInfo(1, 1, 1)
    };

    crimson::dmclock::ClientInfo default_external_client_info = {1, 1, 1};
    std::map<client_profile_id_t,
	     crimson::dmclock::ClientInfo> external_client_infos;
    const crimson::dmclock::ClientInfo *get_external_client(
      const client_profile_id_t &client) const;
  public:
    /**
     * update_from_config
     *
     * Sets the mclock paramaters (reservation, weight, and limit)
     * for each class of IO (background_recovery, background_best_effort,
     * and client).
     */
    void update_from_config(
      const ConfigProxy &conf,
      double capacity_per_shard_thread);
    const crimson::dmclock::ClientInfo *get_info(
      const scheduler_id_t &id) const;
  } client_registry;

  using mclock_queue_t = crimson::dmclock::PullPriorityQueue<
    scheduler_id_t,
    OpSchedulerItem,
    true,
    true,
    2>;
  using priority_t = unsigned;
  using SubQueue = std::map<priority_t,
	std::list<OpSchedulerItem>,
	std::greater<priority_t>>;
  mclock_queue_t scheduler;
  /**
   * high_priority
   *
   * Holds entries to be dequeued in strict order ahead of mClock
   * Invariant: entries are never empty
   */
  SubQueue high_priority;
  priority_t immediate_class_priority = std::numeric_limits<priority_t>::max();

  static scheduler_id_t get_scheduler_id(const OpSchedulerItem &item) {
    return scheduler_id_t{
      item.get_scheduler_class(),
      client_profile_id_t()
    };
  }

  static unsigned int get_io_prio_cut(CephContext *cct) {
    if (cct->_conf->osd_op_queue_cut_off == "debug_random") {
      std::random_device rd;
      std::mt19937 random_gen(rd());
      return (random_gen() % 2 < 1) ? CEPH_MSG_PRIO_HIGH : CEPH_MSG_PRIO_LOW;
    } else if (cct->_conf->osd_op_queue_cut_off == "high") {
      return CEPH_MSG_PRIO_HIGH;
    } else {
      // default / catch-all is 'low'
      return CEPH_MSG_PRIO_LOW;
    }
  }

  unsigned cutoff_priority = get_io_prio_cut(cct);

  /**
   * set_osd_capacity_params_from_config
   *
   * mClockScheduler uses two parameters, osd_bandwidth_cost_per_io
   * and osd_bandwidth_capacity_per_shard_thread, internally.  These
   * two parameters are derived from config parameters
   * osd_mclock_max_capacity_iops_(hdd|ssd) and
   * osd_mclock_max_sequential_bandwidth_(hdd|ssd) as well as
   * num_op_shard_threads. Invoking set_osd_capacity_params_from_config()
   * resets those derived params based on the current config and should be
   * invoked any time they are modified as well as in the constructor.
   * See handle_conf_change().
   */
  void set_osd_capacity_params_from_config();

  // Set the mclock related config params based on the profile
  void set_config_defaults_from_profile();

public: 
  mClockScheduler(CephContext *cct, int whoami, uint32_t num_op_shard_threads,
    int shard_id, bool is_rotational, MonClient *monc);
  ~mClockScheduler() override;

  /// Calculate scaled cost per item
  uint32_t calc_scaled_cost(int cost);

  // Helper method to display mclock queues
  std::string display_queues() const;

  // Enqueue op in the back of the regular queue
  void enqueue(OpSchedulerItem &&item) final;

  // Enqueue the op in the front of the high priority queue
  void enqueue_front(OpSchedulerItem &&item) final;

  // Return an op to be dispatch
  WorkItem dequeue() final;

  // Returns if the queue is empty
  bool empty() const final {
    return scheduler.empty() && high_priority.empty();
  }

  // Formatted output of the queue
  void dump(ceph::Formatter &f) const final;

  void print(std::ostream &ostream) const final {
    ostream << "mClockScheduler";
  }

  // Update data associated with the modified mclock config key(s)
  void update_configuration() final;

  const char** get_tracked_conf_keys() const final;
  void handle_conf_change(const ConfigProxy& conf,
			  const std::set<std::string> &changed) final;
private:
  // Enqueue the op to the high priority queue
  void enqueue_high(unsigned prio, OpSchedulerItem &&item, bool front = false);
};

}

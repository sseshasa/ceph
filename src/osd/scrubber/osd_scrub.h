// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once
#include <string_view>

#include "osd/osd_types_fmt.h"
#include "osd/scrubber/osd_scrub_sched.h"
#include "osd/scrubber/scrub_resources.h"
#include "osd/scrubber_common.h"

/**
 *  Off-loading scrubbing initiation logic from the OSD.
 *  Also here: CPU load as pertaining to scrubs (TBD), and the scrub
 *  resource counters.
 *
 *  Locking:
 *  (as of this first step in the scheduler refactoring)
 *  - No protected data is maintained directly by the OsdScrub object
 *    (as it is not yet protected by any single OSDservice lock).
 */
class OsdScrub {
 public:
  OsdScrub(
      CephContext* cct,
      Scrub::ScrubSchedListener& osd_svc,
      const ceph::common::ConfigProxy& config);

  ~OsdScrub() = default;

  // note: public, as accessed by the dout macros
  std::ostream& gen_prefix(std::ostream& out, std::string_view fn) const;

  /**
   * called periodically by the OSD to select the first scrub-eligible PG
   * and scrub it.
   */
  void initiate_scrub(bool active_recovery);

  /**
   * logs a string at log level 20, using OsdScrub's prefix.
   * An aux function to be used by sub-objects.
   */
  void log_fwd(std::string_view text);

  const Scrub::ScrubResources& resource_bookkeeper() const
  {
    return m_resource_bookkeeper;
  }

  void dump_scrubs(ceph::Formatter* f) const;  ///< fwd to the queue

  /**
   * on_config_change() (the refactored "OSD::sched_all_scrubs()")
   *
   * for each PG registered with the OSD (i.e. - for which we are the primary):
   * lock that PG, and call its on_scrub_schedule_input_change() method
   * to handle a possible change in one of the configuration parameters
   * that affect scrub scheduling.
   */
  void on_config_change();


  // implementing the PGs interface to the scrub scheduling objects
  // ---------------------------------------------------------------

  // updating the resource counters
  bool inc_scrubs_local();
  void dec_scrubs_local();
  bool inc_scrubs_remote(pg_t pgid);
  void dec_scrubs_remote(pg_t pgid);

  // counting the number of PGs stuck while scrubbing, waiting for objects
  void mark_pg_scrub_blocked(spg_t blocked_pg);
  void clear_pg_scrub_blocked(spg_t blocked_pg);

  // updating scheduling information for a specific PG
  Scrub::sched_params_t determine_scrub_time(
      const requested_scrub_t& request_flags,
      const pg_info_t& pg_info,
      const pool_opts_t& pool_conf) const;

  /**
   * modify a scrub-job's scheduled time and deadline
   *
   * There are 3 argument combinations to consider:
   * - 'must' is asserted, and the suggested time is 'scrub_must_stamp':
   *   the registration will be with "beginning of time" target, making the
   *   scrub-job eligible to immediate scrub (given that external conditions
   *   do not prevent scrubbing)
   *
   * - 'must' is asserted, and the suggested time is 'now':
   *   This happens if our stats are unknown. The results are similar to the
   *   previous scenario.
   *
   * - not a 'must': we take the suggested time as a basis, and add to it some
   *   configuration / random delays.
   *
   *  ('must' is Scrub::sched_params_t.is_must)
   *
   *  locking: not using the jobs_lock
   */
  void update_job(
      Scrub::ScrubJobRef sjob,
      const Scrub::sched_params_t& suggested);

  /**
   * Add the scrub job to the list of jobs (i.e. list of PGs) to be periodically
   * scrubbed by the OSD.
   * The registration is active as long as the PG exists and the OSD is its
   * primary.
   *
   * See update_job() for the handling of the 'suggested' parameter.
   *
   * locking: might lock jobs_lock
   */
  void register_with_osd(
      Scrub::ScrubJobRef sjob,
      const Scrub::sched_params_t& suggested);

  /**
   * remove the pg from set of PGs to be scanned for scrubbing.
   * To be used if we are no longer the PG's primary, or if the PG is removed.
   */
  void remove_from_osd_queue(Scrub::ScrubJobRef sjob);

  /**
   * \returns std::chrono::milliseconds indicating how long to wait between
   * chunks.
   *
   * Implementation Note: Returned value is either osd_scrub_sleep or
   * osd_scrub_extended_sleep, depending on must_scrub_param and time
   * of day (see configs osd_scrub_begin*)
   */
  std::chrono::milliseconds scrub_sleep_time(
      utime_t t,
      bool high_priority_scrub) const;

  /**
   * No new scrub session will start while a scrub was initiated on a PG,
   * and that PG is trying to acquire replica resources.
   * \retval false if the flag was already set (due to a race)
   */
  bool set_reserving_now(spg_t reserving_id, utime_t now_is);

  void clear_reserving_now(spg_t reserving_id);

  /**
   * \returns true if the current time is within the scrub time window
   */
  [[nodiscard]] bool scrub_time_permit(utime_t t) const;

  /**
   * An external interface into the LoadTracker object. Used by
   * the OSD tick to update the load data in the logger.
   *
   * \returns 100*(the decaying (running) average of the CPU load
   *          over the last 24 hours) or nullopt if the load is not
   *          available.
   * Note that the multiplication by 100 is required by the logger interface
   */
  std::optional<double> update_load_average();

 private:
  CephContext* cct;
  Scrub::ScrubSchedListener& m_osd_svc;
  const ceph::common::ConfigProxy& conf;

  /**
   * check the OSD-wide environment conditions (scrub resources, time, etc.).
   * These may restrict the type of scrubs we are allowed to start, or just
   * prevent us from starting any scrub at all.
   *
   * Specifically:
   * a nullopt is returned if we are not allowed to scrub at all, for either of
   * the following reasons: no local resources (too many scrubs on this OSD);
   * a dice roll says we will not scrub in this tick;
   * a recovery is in progress, and we are not allowed to scrub while recovery;
   * a PG is trying to acquire replica resources.
   *
   * If we are allowed to scrub, the returned value specifies whether the only
   * high priority scrubs or only overdue ones are allowed to go on.
   */
  std::optional<Scrub::OSDRestrictions> restrictions_on_scrubbing(
      bool is_recovery_active,
      utime_t scrub_clock_now) const;

  /**
   * initiate a scrub on a specific PG
   * The PG is locked, enabling us to query its state. Specifically, we
   * verify that the PG is not already scrubbing, and that
   * a possible 'allow requested repair only' condition is not in conflict.
   *
   * \returns a schedule_result_t object, indicating whether the scrub was
   *          initiated, and if not - why.
   */
  Scrub::schedule_result_t initiate_a_scrub(
      spg_t pgid,
      bool allow_requested_repair_only);

  /// resource reservation management
  Scrub::ScrubResources m_resource_bookkeeper;

  /// the queue of PGs waiting to be scrubbed
  ScrubQueue m_queue;

  const std::string m_log_prefix{};

  /// number of PGs stuck while scrubbing, waiting for objects
  int get_blocked_pgs_count() const;

  /**
   * roll a dice to determine whether we should skip this tick, not trying to
   * schedule a new scrub.
   * \returns true with probability of osd_scrub_backoff_ratio.
   */
  bool scrub_random_backoff() const;

  /**
   * tracking the average load on the CPU. Used both by the
   * OSD logger, and by the scrub queue (as no scrubbing is allowed if
   * the load is too high).
   */
  class LoadTracker {
    CephContext* cct;
    const ceph::common::ConfigProxy& conf;
    const std::string log_prefix;
    double daily_loadavg{0.0};

   public:
    explicit LoadTracker(
	CephContext* cct,
	const ceph::common::ConfigProxy& config,
	int node_id);

    std::optional<double> update_load_average();

    [[nodiscard]] bool scrub_load_below_threshold() const;

    std::ostream& gen_prefix(std::ostream& out, std::string_view fn) const;
  };
  LoadTracker m_load_tracker;
};

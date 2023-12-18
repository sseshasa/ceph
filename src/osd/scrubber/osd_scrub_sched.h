// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once
// clang-format off
/*
┌───────────────────────┐
│ OSD                   │
│ OSDService            │
│                       │
│ ┌─────────────────────│
│ │                     │
│ │   OsdScrub          │
│ │                    ─┼───┐
│ │                     │   │
└───────────────────────┘   │   Ownes & uses the following
                            │   ScrubQueue interfaces:
                            │
                            │
                            │   - resource management (*1)
                            │
                            │   - environment conditions (*2)
                            │
                            │   - scrub scheduling (*3)
                            │
                            │
                            │
 ScrubQueue                 │
┌───────────────────────────▼────────────┐
│                                        │
│                                        │
│  ScrubQContainer    to_scrub <>────────┼────────┐
│  ScrubQContainer    penalized          │        │
│                                        │        │
│                                        │        │
│  OSD_wide resource counters            │        │
│                                        │        │
│                                        │        │
│  "env scrub conditions" monitoring     │        │
│                                        │        │
│                                        │        │
│                                        │        │
│                                        │        │
└─▲──────────────────────────────────────┘        │
  │                                               │
  │                                               │
  │uses interface <4>                             │
  │                                               │
  │                                               │
  │            ┌──────────────────────────────────┘
  │            │                 shared ownership of jobs
  │            │
  │      ┌─────▼──────┐
  │      │ScrubJob    │
  │      │            ├┐
  │      │            ││
  │      │            │┼┐
  │      │            │┼│
  └──────┤            │┼┤◄──────┐
         │            │┼│       │
         │            │┼│       │
         │            │┼│       │
         └┬───────────┼┼│       │shared ownership
          └─┼┼┼┼┼┼┼┼┼┼┼┼│       │
            └───────────┘       │
                                │
                                │
                                │
                                │
┌───────────────────────────────┼─┐
│                               <>│
│PgScrubber                       │
│                                 │
│                                 │
│                                 │
│                                 │
│                                 │
└─────────────────────────────────┘


ScrubQueue interfaces (main functions):

<1> - OSD/PG resources management:

  - can_inc_scrubs()
  - {inc/dec}_scrubs_{local/remote}()
  - dump_scrub_reservations()
  - {set/clear/is}_reserving_now()

<2> - environment conditions:

  - update_loadavg()

  - scrub_load_below_threshold()
  - scrub_time_permit()

<3> - scheduling scrubs:

  - select_pg_and_scrub()
  - dump_scrubs()

<4> - manipulating a job's state:

  - register_with_osd()
  - remove_from_osd_queue()
  - update_job()

 */
// clang-format on

#include <optional>
#include "utime.h"
#include "osd/scrubber/scrub_job.h"
#include "osd/PG.h"

namespace Scrub {

using namespace ::std::literals;

/// possible outcome when trying to select a PG and scrub it
enum class schedule_result_t {
  scrub_initiated,	    // successfully started a scrub
  target_specific_failure,  // failed to scrub this specific target
  osd_wide_failure	    // failed to scrub any target
};

// the OSD services provided to the scrub scheduler
class ScrubSchedListener {
 public:
  virtual int get_nodeid() const = 0;  // returns the OSD number ('whoami')

  /**
   * locks the named PG, returning an RAII wrapper that unlocks upon
   * destruction.
   * returns nullopt if failing to lock.
   */
  virtual std::optional<PGLockWrapper> get_locked_pg(spg_t pgid) = 0;

  virtual ~ScrubSchedListener() {}
};

}  // namespace Scrub


/**
 * the queue of PGs waiting to be scrubbed.
 * Main operations are scheduling/unscheduling a PG to be scrubbed at a certain
 * time.
 *
 * A "penalty" queue maintains those PGs that have failed to reserve the
 * resources of their replicas. The PGs in this list will be reinstated into the
 * scrub queue when all eligible PGs were already handled, or after a timeout
 * (or if their deadline has passed [[disabled at this time]]).
 */
class ScrubQueue {
 public:
  ScrubQueue(CephContext* cct, Scrub::ScrubSchedListener& osds);
  virtual ~ScrubQueue() = default;

  friend class TestOSDScrub;
  friend class ScrubSchedTestWrapper; ///< unit-tests structure
  using sched_params_t = Scrub::sched_params_t;

  /**
   *  returns the list of all scrub targets that are ready to be scrubbed.
   *  Note that the following changes are expected in the near future (as part
   *  of the scheduling refactoring):
   *  - only one target will be requested by the OsdScrub (the OSD's sub-object
   *    that initiates scrubs);
   *  - that target would name a PG X scrub type;
   *
   * @param restrictions: what types of scrub are allowed, given system status
   *               & config. Some of the preconditions are calculated here.
   */
  std::vector<ScrubTargetId> ready_to_scrub(
      Scrub::OSDRestrictions restrictions, // 4B! copy
      utime_t scrub_tick);

  /**
   * remove the pg from set of PGs to be scanned for scrubbing.
   * To be used if we are no longer the PG's primary, or if the PG is removed.
   */
  void remove_from_osd_queue(Scrub::ScrubJobRef sjob);

  /**
   * @return the list (not std::set!) of all scrub jobs registered
   *   (apart from PGs in the process of being removed)
   */
  Scrub::ScrubQContainer list_registered_jobs() const;

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
  void register_with_osd(Scrub::ScrubJobRef sjob, const sched_params_t& suggested);

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
   *  ('must' is sched_params_t.is_must)
   *
   *  locking: not using the jobs_lock
   */
  void update_job(Scrub::ScrubJobRef sjob, const sched_params_t& suggested);

  sched_params_t determine_scrub_time(const requested_scrub_t& request_flags,
				      const pg_info_t& pg_info,
				      const pool_opts_t& pool_conf) const;

  std::ostream& gen_prefix(std::ostream& out, std::string_view fn) const;

 public:
  void dump_scrubs(ceph::Formatter* f) const;

  /**
   * No new scrub session will start while a scrub was initiated on a PG,
   * and that PG is trying to acquire replica resources.
   *
   * \todo replace the atomic bool with a regular bool protected by a
   * common OSD-service lock. Or better still - once PR#53263 is merged,
   * remove this flag altogether.
   */

  /**
   * set_reserving_now()
   * \returns 'false' if the flag was already set
   * (which is a possible result of a race between the check in OsdScrub and
   * the initiation of a scrub by some other PG)
   */
  bool set_reserving_now(spg_t reserving_id, utime_t now_is);

  /**
   * silently ignore attempts to clear the flag if it was not set by
   * the named pg.
   */
  void clear_reserving_now(spg_t reserving_id);
  bool is_reserving_now() const;

  /// counting the number of PGs stuck while scrubbing, waiting for objects
  void mark_pg_scrub_blocked(spg_t blocked_pg);
  void clear_pg_scrub_blocked(spg_t blocked_pg);
  int get_blocked_pgs_count() const;

 private:
  CephContext* cct;
  Scrub::ScrubSchedListener& osd_service;

#ifdef WITH_SEASTAR
  auto& conf() const { return local_conf(); }
#else
  auto& conf() const { return cct->_conf; }
#endif

  /**
   *  jobs_lock protects the job containers and the relevant scrub-jobs state
   *  variables. Specifically, the following are guaranteed:
   *  - 'in_queues' is asserted only if the job is in one of the queues;
   *  - a job will only be in state 'registered' if in one of the queues;
   *  - no job will be in the two queues simultaneously;
   *
   *  Note that PG locks should not be acquired while holding jobs_lock.
   */
  mutable ceph::mutex jobs_lock = ceph::make_mutex("ScrubQueue::jobs_lock");

  Scrub::ScrubQContainer to_scrub;   ///< scrub jobs (i.e. PGs) to scrub
  Scrub::ScrubQContainer penalized;  ///< those that failed to reserve remote resources
  bool restore_penalized{false};

  static inline constexpr auto registered_job = [](const auto& jobref) -> bool {
    return jobref->state == Scrub::qu_state_t::registered;
  };

  static inline constexpr auto invalid_state = [](const auto& jobref) -> bool {
    return jobref->state == Scrub::qu_state_t::not_registered;
  };

  /**
   * Are there scrub jobs that should be reinstated?
   */
  void scan_penalized(bool forgive_all, utime_t time_now);

  /**
   * clear dead entries (unregistered, or belonging to removed PGs) from a
   * queue. Job state is changed to match new status.
   */
  void rm_unregistered_jobs(Scrub::ScrubQContainer& group);

  /**
   * the set of all scrub jobs in 'group' which are ready to be scrubbed
   * (ready = their scheduled time has passed).
   * The scrub jobs in the new collection are sorted according to
   * their scheduled time.
   *
   * Note that the returned container holds independent refs to the
   * scrub jobs.
   * Note also that OSDRestrictions is 1L size, thus copied.
   */
  Scrub::ScrubQContainer collect_ripe_jobs(
      Scrub::ScrubQContainer& group,
      Scrub::OSDRestrictions restrictions,
      utime_t time_now);

  /**
   * The scrubbing of PGs might be delayed if the scrubbed chunk of objects is
   * locked by some other operation. A bug might cause this to be an infinite
   * delay. If that happens, the OSDs "scrub resources" (i.e. the
   * counters that limit the number of concurrent scrub operations) might
   * be exhausted.
   * We do issue a cluster-log warning in such occasions, but that message is
   * easy to miss. The 'some pg is blocked' global flag is used to note the
   * existence of such a situation in the scrub-queue log messages.
   */
  std::atomic_int_fast16_t blocked_scrubs_cnt{0};

  /**
   * One of the OSD's primary PGs is in the initial phase of a scrub,
   * trying to secure its replicas' resources. We will refrain from initiating
   * any other scrub sessions until this one is done.
   *
   * \todo replace the local lock with regular osd-service locking
   */
  ceph::mutex reserving_lock = ceph::make_mutex("ScrubQueue::reserving_lock");
  std::optional<spg_t> reserving_pg;
  utime_t reserving_since;

  /**
   * If the scrub job was not explicitly requested, we postpone it by some
   * random length of time.
   * And if delaying the scrub - we calculate, based on pool parameters, a
   * deadline we should scrub before.
   *
   * @return a pair of values: the determined scrub time, and the deadline
   */
  Scrub::scrub_schedule_t adjust_target_time(
    const Scrub::sched_params_t& recomputed_params) const;

  /**
   * Look for scrub jobs that have their 'resources_failure' set. These jobs
   * have failed to acquire remote resources last time we've initiated a scrub
   * session on them. They are now moved from the 'to_scrub' queue to the
   * 'penalized' set.
   *
   * locking: called with job_lock held
   */
  void move_failed_pgs(utime_t now_is);

protected: // used by the unit-tests
  /**
   * unit-tests will override this function to return a mock time
   */
  virtual utime_t time_now() const { return ceph_clock_now(); }
};

#include "DaemonHealthMetricCollector.h"

#include <fmt/format.h>

#include "include/container_ios.h"
#include "include/health.h"
#include "include/types.h"

#include <sstream>
#include <vector>

namespace {

using std::unique_ptr;
using std::vector;
using std::ostringstream;

class SlowOps final : public DaemonHealthMetricCollector {
  bool _is_relevant(daemon_metric type) const override {
    return type == daemon_metric::SLOW_OPS;
  }
  health_check_t& _get_check(health_check_map_t& cm) const override {
    return cm.get_or_add("SLOW_OPS", HEALTH_WARN, "", 1);
  }
  bool _update(const DaemonKey& daemon,
               const DaemonHealthMetric& metric) override {
    auto num_slow = metric.get_n1();
    auto blocked_time = metric.get_n2();
    value.n1 += num_slow;
    value.n2 = std::max(value.n2, blocked_time);
    if (num_slow || blocked_time) {
      daemons.push_back(daemon);
      return true;
    } else {
      return false;
    }
  }
  void _summarize(health_check_t& check) const override {
    if (daemons.empty()) {
      return;
    }
    // Note this message format is used in mgr/prometheus, so any change in format
    // requires a corresponding change in the mgr/prometheus module.
    ostringstream ss;
    if (daemons.size() > 1) {
      if (daemons.size() > 10) {
        ss << "daemons " << vector<DaemonKey>(daemons.begin(), daemons.begin()+10)
           << "..." << " have slow ops.";
      } else {
        ss << "daemons " << daemons << " have slow ops.";
      }
    } else {
      ss << daemons.front() << " has slow ops";
    }
    check.summary =
        fmt::format("{} slow ops, oldest one blocked for {} sec, {}",
                    value.n1, value.n2, ss.str());
    // No detail
  }
  vector<DaemonKey> daemons;
};


class PendingPGs final : public DaemonHealthMetricCollector {
  bool _is_relevant(daemon_metric type) const override {
    return type == daemon_metric::PENDING_CREATING_PGS;
  }
  health_check_t& _get_check(health_check_map_t& cm) const override {
    return cm.get_or_add("PENDING_CREATING_PGS", HEALTH_WARN, "", 1);
  }
  bool _update(const DaemonKey& osd,
               const DaemonHealthMetric& metric) override {
    value.n += metric.get_n();
    if (metric.get_n()) {
      osds.push_back(osd);
      return true;
    } else {
      return false;
    }
  }
  void _summarize(health_check_t& check) const override {
    if (osds.empty()) {
      return;
    }
    check.summary = fmt::format("{} PGs pending on creation", value.n);
    ostringstream ss;
    if (osds.size() > 1) {
      ss << "osds " << osds << " have pending PGs.";
    } else {
      ss << osds.front() << " has pending PGs";
    }
    check.detail.push_back(ss.str());
  }
  vector<DaemonKey> osds;
};

class HighDebugLevel final : public DaemonHealthMetricCollector {
  bool _is_relevant(daemon_metric type) const override {
    return type == daemon_metric::HIGH_DEBUG_LEVEL;
  }
  health_check_t& _get_check(health_check_map_t& cm) const override {
    return cm.get_or_add("HIGH_DEBUG_LEVEL", HEALTH_WARN, "", 1);
  }
  bool _update(const DaemonKey& daemon,
               const DaemonHealthMetric& metric) override {
    // n1 = number of elevated subsystems, n2 = max level
    auto num_elevated = metric.get_n1();
    auto max_level = metric.get_n2();
    value.n1 += num_elevated;
    value.n2 = std::max(value.n2, max_level);
    if (num_elevated) {
      daemons.push_back(daemon);
      return true;
    }
    return false;
  }
  void _summarize(health_check_t& check) const override {
    if (daemons.empty()) {
      return;
    }
    ostringstream ss;
    if (daemons.size() > 1) {
      if (daemons.size() > 10) {
        ss << vector<DaemonKey>(daemons.begin(), daemons.begin()+10) << "...";
      } else {
        ss << daemons;
      }
    } else {
      ss << daemons.front();
    }
    check.summary =
      fmt::format("{} subsystems across {} daemon(s) have high debug levels (max {}): {}",
                  value.n1, daemons.size(), value.n2, ss.str());
  }
  vector<DaemonKey> daemons;

// Collector for mClock periodic IOPS bench degradation health checks.
// n1 = severity (0=healthy, 1=warn, 2=error); n2 = integer drop percentage.
// A severity of 0 means the OSD is within acceptable range - _update returns
// false and the check is not added to the health map (i.e. it self-clears).
class MClockIopsDegraded final : public DaemonHealthMetricCollector {
  bool _is_relevant(daemon_metric type) const override {
    return type == daemon_metric::MCLOCK_IOPS_DEGRADED;
  }
  health_check_t& _get_check(health_check_map_t& cm) const override {
    health_status_t sev = (max_severity >= 2) ? HEALTH_ERR : HEALTH_WARN;
    return cm.get_or_add("OSD_MCLOCK_IOPS_DEGRADED", sev, "", 1);
  }
  bool _update(const DaemonKey& daemon,
               const DaemonHealthMetric& metric) override {
    uint32_t sev  = metric.get_n1();
    uint32_t drop = metric.get_n2();
    if (sev == 0) {
      return false; // healthy - do not report
    }
    max_severity = std::max(max_severity, sev);
    entries.push_back({daemon, sev, drop});
    return true;
  }
  void _summarize(health_check_t& check) const override {
    if (entries.empty()) {
      return;
    }
    if (entries.size() == 1) {
      const auto& e = entries.front();
      check.summary = fmt::format(
        "{}.{} mClock IOPS {}% below boot baseline ({})",
        e.daemon.type,
        e.daemon.name,
        e.drop_pct,
        e.severity >= 2 ? "severe degradation - check disk health immediately"
                        : "possible early degradation - consider checking disk health");
    } else {
      uint32_t worst_drop = 0;
      for (const auto& e : entries) {
        worst_drop = std::max(worst_drop, e.drop_pct);
      }
      check.summary = fmt::format(
        "{} OSDs have degraded mClock IOPS (worst: {}% below boot baseline)",
        entries.size(), worst_drop);
      for (const auto& e : entries) {
        check.detail.push_back(fmt::format(
          "{}.{} mClock IOPS {}% below boot baseline",
          e.daemon.type, e.daemon.name, e.drop_pct));
      }
    }
  }

  struct Entry {
    DaemonKey daemon;
    uint32_t severity;
    uint32_t drop_pct;
  };
  uint32_t max_severity = 0;
  vector<Entry> entries;
};

} // anonymous namespace

unique_ptr<DaemonHealthMetricCollector>
DaemonHealthMetricCollector::create(daemon_metric m)
{
  switch (m) {
  case daemon_metric::SLOW_OPS:
    return std::make_unique<SlowOps>();
  case daemon_metric::PENDING_CREATING_PGS:
    return std::make_unique<PendingPGs>();
  case daemon_metric::HIGH_DEBUG_LEVEL:
    return std::make_unique<HighDebugLevel>();
  case daemon_metric::MCLOCK_IOPS_DEGRADED:
    return std::make_unique<MClockIopsDegraded>();
  default:
    return {};
  }
}

"""
Memory Channel Interleaving & Topology Optimization Engine for VCF 9.1.
"""
import re
from typing import Optional


def evaluate_memory_topology(mem_details: dict, cpu_summary: Optional[dict] = None) -> dict:
    """
    Analyzes memory channel interleaving, socket population balance, clock speeds,
    and module capacities for modern server CPU architectures (Intel/AMD).
    Returns a dict with score, status badge, layout grid, findings, and recommendations.
    """
    if not cpu_summary:
        cpu_summary = {}
    cpu_count = int(cpu_summary.get("count") or cpu_summary.get("cpu_count") or 1)
    chan_per_cpu = int(cpu_summary.get("channels_per_socket") or cpu_summary.get("channels") or 8)
    max_ram_speed = int(cpu_summary.get("max_ram_speed_mhz") or 0)

    # Make a shallow copy of dimm_list entries so caller dictionaries are not mutated
    raw_dimms = mem_details.get("dimm_list") or []
    dimm_list = [dict(d) for d in raw_dimms]

    # Group DIMMs by Socket and Channel
    sockets = {}
    all_speeds = set()        # actual operating speeds (OperatingSpeedMhz)
    all_rated_speeds = set()  # rated ceiling speeds (AllowedSpeedsMHz max)
    all_capacities = set()
    total_ram_gb = 0

    # Check if socket numbers in dimm_list are 0-indexed (e.g. 0 and 1)
    raw_sockets = [int(d["socket"]) for d in dimm_list if d.get("socket") is not None]
    if raw_sockets and min(raw_sockets) == 0:
        for d in dimm_list:
            if d.get("socket") is not None:
                d["socket"] = int(d["socket"]) + 1

    for d in dimm_list:
        s_val = d.get("socket")
        s_id = int(s_val) if s_val is not None else 1
        slot_str = str(d.get("slot") or "").strip().upper()

        m_dell = re.search(r"\bDIMM\s+([A-D])\s*(\d+)\b", slot_str)
        if m_dell and chan_per_cpu > 0:
            s_id = ord(m_dell.group(1)) - ord('A') + 1
            slot_num = int(m_dell.group(2))
            ch_id = chr(ord('A') + (slot_num - 1) % chan_per_cpu)
            d["socket"] = s_id
            d["channel"] = ch_id
        else:
            ch_id = str(d.get("channel") or "A").upper()[:1]
            if not ch_id.isalpha():
                ch_id = "A"
            if chan_per_cpu > 0:
                ch_offset = ord(ch_id) - ord('A')
                if ch_offset >= chan_per_cpu:
                    ch_id = chr(ord('A') + (ch_offset % chan_per_cpu))
                    d["channel"] = ch_id

        cap   = int(d.get("capacity_gb") or 0)
        spd   = int(d.get("speed_mhz") or 0)
        rated = int(d.get("max_speed_mhz") or 0)

        if cap > 0:
            total_ram_gb += cap
            all_capacities.add(cap)
        if spd > 0:
            all_speeds.add(spd)
        if rated > 0:
            all_rated_speeds.add(rated)

        sock_dict = sockets.setdefault(s_id, {})
        chan_list = sock_dict.setdefault(ch_id, [])
        chan_list.append(d)

    # Ensure entries exist for all expected sockets up to cpu_count
    for s_id in range(1, cpu_count + 1):
        sockets.setdefault(s_id, {})

    issues = []
    recommendations = []

    # Rule 1: Socket Balance
    sock_caps = {s: sum(d.get("capacity_gb", 0) for ch in chans.values() for d in ch) for s, chans in sockets.items()}
    sock_counts = {s: sum(len(ch) for ch in chans.values()) for s, chans in sockets.items()}

    if cpu_count >= 2:
        s1_gb = sock_caps.get(1, 0)
        s2_gb = sock_caps.get(2, 0)
        if s1_gb != s2_gb:
            issues.append(
                f"<b>Asymmetric Socket Memory Allocation:</b> Socket 1 has {s1_gb} GB ({sock_counts.get(1,0)} DIMMs) "
                f"while Socket 2 has {s2_gb} GB ({sock_counts.get(2,0)} DIMMs)."
            )
            recommendations.append(
                "Re-seat DIMMs so memory capacity and DIMM count are equal between Socket 1 and Socket 2 to avoid asymmetric NUMA node latency."
            )

    # Rule 2: Channel Interleaving
    total_active_chans = 0
    total_expected_chans = cpu_count * chan_per_cpu
    mixed_dpc_sockets = set()
    total_board_slots = int(mem_details.get("slot_count") or mem_details.get("total_slots") or 0)
    slots_per_sock = (total_board_slots // cpu_count) if (total_board_slots and cpu_count) else 0

    for s_id, chans in sockets.items():
        active_ch_count = len([ch for ch, dimms in chans.items() if any(d.get("capacity_gb", 0) > 0 for d in dimms)])
        total_active_chans += active_ch_count
        dimm_count = sock_counts.get(s_id, 0)

        if dimm_count > 0:
            if active_ch_count < chan_per_cpu:
                eff = round((active_ch_count / chan_per_cpu) * 100)
                no_free_slots = (slots_per_sock > 0 and dimm_count >= slots_per_sock)
                fewer_slots_than_chans = (slots_per_sock > 0 and slots_per_sock < chan_per_cpu)

                if no_free_slots or fewer_slots_than_chans:
                    _avail_lbl = f"{slots_per_sock} physical slot(s)" if slots_per_sock else f"{dimm_count} slot(s)"
                    issues.append(
                        f"<b>Partial Memory Interleaving on Socket {s_id}:</b> {active_ch_count} of {chan_per_cpu} channels active ({dimm_count} DIMMs). "
                        f"Motherboard provides {_avail_lbl} per socket. Memory bus operating at ~{eff}% bandwidth capacity."
                    )
                    recommendations.append(
                        f"All {dimm_count} physical DIMM slot(s) on Socket {s_id} are populated. "
                        f"Replace existing DIMMs with higher-capacity modules if additional total RAM is required."
                    )
                else:
                    issues.append(
                        f"<b>Sub-Optimal Memory Interleaving on Socket {s_id}:</b> {active_ch_count} of {chan_per_cpu} channels active ({dimm_count} DIMMs). "
                        f"Memory bus operating at ~{eff}% bandwidth capacity."
                    )
                    recommendations.append(
                        f"Install {chan_per_cpu - active_ch_count} additional DIMM(s) on Socket {s_id} in empty channels to enable full {chan_per_cpu}-channel interleaving."
                    )
            elif dimm_count % chan_per_cpu != 0:
                # Mixed 1DPC + 2DPC: some channels have one DIMM, others have two.
                # Intel/AMD memory controllers prefer uniform DIMMs-per-channel.
                dpc_high = (dimm_count + chan_per_cpu - 1) // chan_per_cpu  # ceil
                dpc_low = dimm_count // chan_per_cpu                        # floor
                ch_at_high = dimm_count % chan_per_cpu
                ch_at_low = chan_per_cpu - ch_at_high
                issues.append(
                    f"<b>Mixed DIMMs-Per-Channel (DPC) on Socket {s_id}:</b> {dimm_count} DIMMs across {chan_per_cpu} channels — "
                    f"{ch_at_high} channel(s) at {dpc_high}DPC, {ch_at_low} channel(s) at {dpc_low}DPC. "
                    f"Non-uniform DPC can reduce memory controller efficiency."
                )
                recommendations.append(
                    f"Install DIMMs in multiples of {chan_per_cpu} per socket ({chan_per_cpu} or {chan_per_cpu * 2} DIMMs per socket) for uniform {chan_per_cpu}-channel interleaving."
                )
                mixed_dpc_sockets.add(s_id)

    # ── _fmt_slot helper ────────────────────────────────────────────────
    def _fmt_slot(d):
        """Return 'SLOT [PN: PARTNUM]' when a non-trivial part number is known."""
        pn = str(d.get("part_number") or "").strip()
        slot_name = str(d.get("slot") or "?")
        if pn and pn not in ("N/A", "Unknown", ""):
            return f"{slot_name} [PN: {pn}]"
        return slot_name

    # Rule 3: Speed Downclocking — uses rated ceiling speeds (AllowedSpeedsMHz max)
    # to identify which module(s) are forcing the system to downclock, rather than
    # relying on the operating speed alone (which could be identical for all DIMMs
    # even though some are capable of higher frequencies).
    max_actual_spd = max(all_speeds) if all_speeds else 0
    has_mixed_rated = len(all_rated_speeds) > 1
    intra_chan_speed_mismatches = []  # populated by Rule 5 below

    if has_mixed_rated:
        min_rated = min(all_rated_speeds)
        max_rated = max(all_rated_speeds)
        speed_loss_pct = round((1.0 - min_rated / max_rated) * 100, 1)
        bottleneck_dimms = [d for d in dimm_list if int(d.get("max_speed_mhz") or 0) == min_rated]
        victim_count = sum(1 for d in dimm_list if int(d.get("max_speed_mhz") or 0) > min_rated)
        if len(bottleneck_dimms) <= 3:
            slot_list = ", ".join(_fmt_slot(d) for d in bottleneck_dimms)
            slot_desc = f"slot{'s' if len(bottleneck_dimms) > 1 else ''} {slot_list}"
        else:
            slot_desc = f"{len(bottleneck_dimms)} DIMMs rated at {min_rated} MHz"
        issues.append(
            f"<b>Speed Bottleneck — {slot_desc}:</b> "
            f"{len(bottleneck_dimms)} DIMM{'s' if len(bottleneck_dimms) > 1 else ''} rated for {min_rated} MHz "
            f"{'is' if len(bottleneck_dimms) == 1 else 'are'} forcing {victim_count} other "
            f"module{'s' if victim_count != 1 else ''} (rated {max_rated} MHz) to downclock. "
            f"Effective memory bandwidth reduced by ~{speed_loss_pct}%."
        )
        recommendations.append(
            f"Replace the {min_rated} MHz module{'s' if len(bottleneck_dimms) > 1 else ''} "
            f"with {max_rated} MHz DIMMs to restore full memory bus throughput."
        )
    elif max_ram_speed and max_actual_spd and max_actual_spd < max_ram_speed:
        issues.append(
            f"<b>Memory Operating Below Peak CPU Rated Speed:</b> Installed memory operating at {max_actual_spd} MHz, "
            f"whereas processor architecture supports up to {max_ram_speed} MHz under optimal 1DPC configuration."
        )
        recommendations.append(
            f"Verify BIOS memory speed profiles or upgrade to DIMM modules rated for {max_ram_speed} MHz to achieve maximum memory bus throughput."
        )

    # Rule 4: Mixed Module Capacities — global check + per-channel intra-slot asymmetry.
    # At 2DPC, when two DIMMs in the same channel differ in size the smaller capacity
    # defines the interleaved region; the extra GB on the larger DIMM runs single-rank.
    intra_channel_cap_penalty = False
    if len(all_capacities) > 1:
        caps_sorted = sorted(list(all_capacities))
        issues.append(
            f"<b>Mixed Memory Module Capacities Detected:</b> Found mixed sizes ({', '.join(str(c)+' GB' for c in caps_sorted)}). "
            "Breaks symmetric interleaving across channel pairs — non-interleaved regions operate at reduced bandwidth."
        )
        recommendations.append("Standardize on identical DIMM capacities per channel group for optimal vSAN ESA memory throughput.")

        intra_channel_cap_mismatches = []
        for s_id, chans in sockets.items():
            for ch_id, dimms in chans.items():
                pop = [d for d in dimms if d.get("capacity_gb", 0) > 0]
                if len(pop) >= 2:
                    ch_caps = [d.get("capacity_gb", 0) for d in pop]
                    if len(set(ch_caps)) > 1:
                        min_cap = min(ch_caps)
                        max_cap = max(ch_caps)
                        outliers = [d for d in pop if d.get("capacity_gb", 0) == max_cap]
                        outlier_strs = ", ".join(_fmt_slot(d) for d in outliers[:3])
                        non_interleaved_gb = (max_cap - min_cap) * len(outliers)
                        intra_channel_cap_mismatches.append({
                            "socket": s_id, "channel": ch_id,
                            "non_interleaved_gb": non_interleaved_gb,
                            "outlier_str": outlier_strs,
                            "max_cap": max_cap, "min_cap": min_cap,
                        })
        if intra_channel_cap_mismatches:
            intra_channel_cap_penalty = True
            total_non_interleaved = sum(m["non_interleaved_gb"] for m in intra_channel_cap_mismatches)
            for m in intra_channel_cap_mismatches:
                issues.append(
                    f"<b>Intra-Channel Capacity Asymmetry — Socket {m['socket']} / Channel {m['channel']}:</b> "
                    f"{m['outlier_str']} ({m['max_cap']} GB) is paired with a {m['min_cap']} GB DIMM. "
                    f"The extra {m['non_interleaved_gb']} GB operates outside the interleaved region at reduced bandwidth."
                )
            recommendations.append(
                f"Standardize channel pairs to identical capacity. "
                f"Total non-interleaved memory across affected channels: {total_non_interleaved} GB."
            )

    # Rule 5: Intra-Channel Speed Ceiling Mismatch at 2DPC
    # If two DIMMs sharing a channel have different AllowedSpeedsMHz ceilings,
    # the slower module limits that channel regardless of system-wide speed.
    for s_id, chans in sockets.items():
        for ch_id, dimms in chans.items():
            pop = [d for d in dimms if d.get("capacity_gb", 0) > 0]
            if len(pop) >= 2:
                ch_rated = [int(d.get("max_speed_mhz") or 0) for d in pop
                            if int(d.get("max_speed_mhz") or 0) > 0]
                if len(ch_rated) >= 2 and len(set(ch_rated)) > 1:
                    ch_min = min(ch_rated)
                    ch_max = max(ch_rated)
                    slower = next((d for d in pop if int(d.get("max_speed_mhz") or 0) == ch_min), None)
                    faster = next((d for d in pop if int(d.get("max_speed_mhz") or 0) == ch_max), None)
                    intra_chan_speed_mismatches.append({
                        "socket": s_id, "channel": ch_id,
                        "slower_slot": _fmt_slot(slower) if slower else "?",
                        "faster_slot": _fmt_slot(faster) if faster else "?",
                        "ch_min": ch_min, "ch_max": ch_max,
                    })
    if intra_chan_speed_mismatches:
        for m in intra_chan_speed_mismatches:
            issues.append(
                f"<b>2DPC Speed Ceiling Mismatch — Socket {m['socket']} Channel {m['channel']}:</b> "
                f"{m['slower_slot']} ({m['ch_min']} MHz rated) is paired with "
                f"{m['faster_slot']} ({m['ch_max']} MHz rated). "
                f"This channel pair runs at {m['ch_min']} MHz regardless of the system-wide speed."
            )
        recommendations.append(
            "Swap mismatched 2DPC modules so both DIMMs in each channel share the same rated speed ceiling."
        )

    # Rule 6: DIMM Health State
    # Redfish Status.Health: OK / Warning / Critical
    # Status.State non-operational values: Disabled, UnavailableOffline, InTest,
    #   Updating, StandbyOffline, StandbySpare, Quiesced, Deferring
    _NON_OP_STATES = {"disabled", "unavailableoffline", "intest", "updating",
                      "standbyoffline", "standbyspare", "quiesced", "deferring"}
    failed_dimms = mem_details.get("failed_dimms") or []
    health_critical_count = 0
    health_warning_count  = 0
    health_state_count    = 0
    for fd in failed_dimms:
        fslot   = _fmt_slot(fd)
        fhealth = str(fd.get("health") or "").strip().lower()
        fstate  = str(fd.get("state")  or "").strip().lower()
        if fhealth == "critical":
            health_critical_count += 1
            issues.append(
                f"<b>DIMM Hardware Fault — {fslot} [Critical]:</b> "
                f"Redfish reports <code>Status.Health=Critical</code>. This module may be causing "
                f"uncorrectable ECC errors or has been mapped out by the memory controller. "
                f"Inspect System Event Log and replace immediately."
            )
        elif fhealth == "warning":
            health_warning_count += 1
            issues.append(
                f"<b>DIMM Degraded — {fslot} [Warning]:</b> "
                f"Redfish reports <code>Status.Health=Warning</code>. Correctable single-bit ECC errors "
                f"are likely accumulating. Monitor SEL for correctable error counts and schedule replacement."
            )
        elif fstate in _NON_OP_STATES:
            health_state_count += 1
            issues.append(
                f"<b>DIMM Non-Operational — {fslot} [{fd.get('state', '?')}]:</b> "
                f"Redfish reports <code>Status.State={fd.get('state', '?')}</code>. "
                f"Module is present but inactive — verify BIOS memory configuration."
            )
    if failed_dimms:
        recommendations.append(
            "Review System Event Log (SEL) for memory ECC error events on all flagged DIMMs."
        )

    # ── Scoring ─────────────────────────────────────────────────────────
    # Penalties are intentionally moderate: the findings panel calls out specifics.
    # A single DIMM causing multiple conditions should not stack unreasonably —
    # caps prevent runaway degradation from many failing DIMMs.
    base_efficiency = (total_active_chans / max(1, total_expected_chans)) * 100.0
    if cpu_count >= 2 and sock_caps.get(1, 0) != sock_caps.get(2, 0):
        base_efficiency -= 10.0
    if mixed_dpc_sockets:
        base_efficiency -= 10.0
    if has_mixed_rated:
        base_efficiency -= 10.0
    if len(all_capacities) > 1:
        base_efficiency -= 10.0
    if intra_channel_cap_penalty:
        base_efficiency -= 5.0
    if intra_chan_speed_mismatches:
        base_efficiency -= 5.0
    base_efficiency -= min(40.0, health_critical_count * 20.0)
    base_efficiency -= min(20.0, health_warning_count  * 10.0)
    base_efficiency -= min(15.0, health_state_count    *  5.0)

    score_pct = max(10, min(100, round(base_efficiency)))

    # Badge color driven purely by score_pct — issues are shown separately.
    # Thresholds: >=95 Optimal, >=80 Sub-Optimal, <80 Degraded
    if score_pct >= 95:
        badge = f'<span class="badge success">\U0001f7e2 Optimal Interleaving ({score_pct}% Efficiency)</span>'
    elif score_pct >= 80:
        badge = f'<span class="badge warning">\U0001f7e1 Sub-Optimal Interleaving ({score_pct}% Efficiency)</span>'
    else:
        badge = f'<span class="badge danger">\U0001f534 Degraded Memory Topology ({score_pct}% Efficiency)</span>'

    # ── Visualizer Grid ──────────────────────────────────────────────────
    channel_letters = [chr(ord('A') + i) for i in range(chan_per_cpu)]
    visualizer_grid = {}

    def _slot_num(d):
        """Extract trailing numeric slot index for sorting within a channel."""
        m = re.search(r'(\d+)\s*$', str(d.get("slot", "") or ""))
        return int(m.group(1)) if m else 999

    for s_id in range(1, cpu_count + 1):
        s_chans = sockets.get(s_id, {})
        s_grid = {}
        for letter in channel_letters:
            raw = s_chans.get(letter, [])
            # Sort by slot number so primary slot (e.g. A1) always precedes secondary (e.g. A9).
            sorted_dimms = sorted(raw, key=_slot_num)
            if sorted_dimms:
                s_grid[letter] = {
                    "populated": True,
                    "dpc": len(sorted_dimms),
                    "dimms": [
                        {
                            "slot":        d.get("slot", f"Ch {letter}"),
                            "label":       f"{d.get('capacity_gb', 0)}GB {d.get('type', 'DRAM')}",
                            "speed":       f"{d.get('speed_mhz', 0)}MHz" if d.get("speed_mhz") else "",
                            "rated_speed": (
                                f"{d.get('max_speed_mhz')}MHz rated"
                                if d.get("max_speed_mhz") and d.get("max_speed_mhz") != d.get("speed_mhz")
                                else ""
                            ),
                            "health": d.get("health", "OK"),
                            "correctable_ecc": d.get("correctable_ecc"),
                            "uncorrectable_ecc": d.get("uncorrectable_ecc"),
                        }
                        for d in sorted_dimms
                    ],
                }
            else:
                s_grid[letter] = {"populated": False, "dpc": 0, "dimms": []}
        visualizer_grid[f"Socket {s_id}"] = s_grid

    return {
        "interleaving_score_pct": score_pct,
        "status_badge": badge,
        "total_ram_gb": total_ram_gb,
        "active_channels": total_active_chans,
        "expected_channels": total_expected_chans,
        "chan_per_cpu": chan_per_cpu,
        "max_ram_speed_mhz": max_ram_speed,
        "max_ram_speed_str": f"{max_ram_speed} MHz" if max_ram_speed else "N/A",
        "operating_speed_str": f"{max(all_speeds)} MHz" if all_speeds else "N/A",
        "issues": issues,
        "recommendations": recommendations,
        "visualizer_grid": visualizer_grid,
        "socket_counts": sock_counts,
        "socket_caps": sock_caps,
    }


class MemoryInterleavingEngine:
    """Memory Channel Interleaving & Topology Optimization Engine.
    Evaluates memory topology, channel population symmetry, clock speed downclocking,
    and NUMA socket balance for modern Intel and AMD server architectures.
    """
    @staticmethod
    def analyze_memory_topology(mem_details: dict, cpu_summary: Optional[dict] = None) -> dict:
        return evaluate_memory_topology(mem_details, cpu_summary)

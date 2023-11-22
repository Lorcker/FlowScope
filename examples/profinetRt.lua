local ffi = require "ffi"
local lm = require "libmoon"
local pkt_lib = require "packet"
local eth = require "proto.ethernet"
local log = require "log"

local module = {}

INACTIVE_FLOW_EXPIRY = 30         -- in seconds
PROFINET_IO_RT_CYLCE_TIME = 31.25 -- In micro_seconds
------------------------------------------------------------------------------------
---- Defintion of FlowState and FlowKeys
------------------------------------------------------------------------------------
--- profinet_flow_state:    State the track matrics for gerneral flows. For a ProfinetRT cyclic Flow (RT1) there will be addional info stored. Otherwise these values will be 0.
---     first_seen: stored in micro_seconds
---     last_seen: stored in micro_seconds
--- gerneral_flow_key:      Key for a general flow. This key is used for a non ProfinetIO flow. Only information on ethernet layer will be used as key, as upper layers are not that intereseing fot this usecase.
--- pnrt_flow_key:          Key for a ProfinetIO flow. As defined in the IEC standard ProfinetIO packets have a frame_id. With this frame_id one can classify incoming packets.
ffi.cdef [[
    struct profinet_flow_state {
        uint64_t total_packet_counter;
        uint64_t total_byte_counter;
        uint64_t first_seen;
        uint64_t last_seen;

        uint64_t interval_start_time;
        uint32_t interval_packet_counter;
        uint32_t interval_byte_counter;

        uint16_t last_pnrt_cycle_counter;
        float    interval_pnrt_cycle_counter_jitter_max;
        uint16_t interval_pnrt_out_of_order_counter;
        uint16_t interval_pnrt_repetition_counter;
        uint16_t interval_pnrt_dropped_counter;
    };

    struct general_flow_key {
        uint64_t  mac_dst;
        uint64_t  mac_scr;
        uint8_t  ethertype;
    } __attribute__((__packed__));

    struct pnrt_flow_key {
        uint64_t  mac_dst;
        uint64_t  mac_scr;
        uint8_t  ethertype;
        uint16_t frame_id;
    } __attribute__((__packed__));
]]

-- Export flow keys
-- Position in the array corresponds to the index returned by extractFlowKey()
module.flowKeys = {
    "struct general_flow_key",
    "struct pnrt_flow_key",
}

-- Export flow state type
module.stateType = "struct profinet_flow_state"

-- Custom default state for new flows
module.defaultState = {}

------------------------------------------------------------------------------------
---- Analyzer Configuration
------------------------------------------------------------------------------------

--- Function that builds the appropriate flow key for the packet given in buf
--- @param buf any
--- @param keyBuf any
--- @return boolean
function module.extractFlowKey(buf, keyBuf)
    local ethPkt = pkt_lib.getEthernetPacket(buf)

    if ethPkt.eth:getType() == eth.TYPE_PNIO then
        local parsedPkt = pkt_lib.getPnioPacket()

        keyBuf = ffi.cast("struct pnrt_flow_key&", keyBuf)
        keyBuf.mac_dst = ethPkt.eth.getDst()
        keyBuf.mac_src = ethPkt.eth.getSrc()
        keyBuf.ethertype = ethPkt.eth.getType()
        keyBuf.frame_id = parsedPkt.pnio:getFrameId()
    else
        keyBuf = ffi.cast("struct general_flow_key&", keyBuf)
        keyBuf.mac_dst = ethPkt.eth.getDst()
        keyBuf.mac_src = ethPkt.eth.getSrc()
        keyBuf.ethertype = ethPkt.eth.getType()
    end
    return true
end

--- Function for extracting info from PROFINET IO packets and adding it the state
--- @param timestamp any in micro_seconds
--- @param state any
--- @param buf any raw byte buffer
--- @param isFirstPacket boolean
local function handlePnioPacket(timestamp, state, buf, isFirstPacket)
    local parsed_pnio_packet = pkt_lib.getPnioPacket(buf)
    local apdu_status = parsed_pnio_packet.pnio:getApduStatus(parsed_pnio_packet:getSize())
    local cycle_counter = apdu_status:getCycleCounter()

    if isFirstPacket then
        -- No further values can be calculated because last cylceCounter is needed for that
        state.last_pnrt_cycle_counter = cycle_counter
        return
    end

    --- Update state metrics decucable by the cycleCounter
    -- Calculate cylceTime jitter
    local cycle_counter_rel_diff = (cycle_counter + (0x10000 - state.last_pnrt_cycle_counter)) &
        0xFFFF                                                                    -- Calculates distance between the clycle counters. Takes wrap around into consideration.
    local expected_time_diff = cycle_counter_rel_diff * PROFINET_IO_RT_CYLCE_TIME -- In micro_seconds
    local actual_time_diff = state.last_seen - timestamp
    local jitter = (expected_time_diff - actual_time_diff) /
        expected_time_diff -- Percantage deviation from extpected
    state.interval_pnrt_cycle_counter_jitter_max = jitter > state.interval_pnrt_cycle_counter_jitter_max and jitter or
        state.interval_pnrt_cycle_counter_jitter_max

    -- Check if packet is wrong (eg. Wrong order, dulpicate, ...). Criterias are deinfed in IEC61158-6-10 4.7.2.1.2
    local normalized_cycle_counter_diff = (((cycle_counter + (0x10000 - state.last_pnrt_cycle_counter) - 1) & 0xFFFF) - 0xF000) *
        (-1)
    if normalized_cycle_counter_diff == 0 then
        state.interval_pnrt_repetition_counter = state.interval_pnrt_repetition_counter + 1
    elseif normalized_cycle_counter_diff < 0 then
        state.interval_pnrt_out_of_order_counter = state.interval_pnrt_out_of_order_counter + 1
    end
    -- TODO add check to figure out if packet was dropped

    state.last_pnrt_cycle_counter = cycle_counter
end

--- Handles a singel captured packet by extracting information from buff and flowKey and storing it in state
--- @param flowKey any One of the above defined flow keys
--- @param state any Starts out empty if it doesn't exist yet
--- @param buf any Whatever the device queue or QQ gives us
--- @param isFirstPacket boolean
function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local ts = buf:getTimestamp() * 10 ^ 6 -- Shift float to get more digits to store in a uint in seconds
    state.first_seen = isFirstPacket and ts or state.first_seen

    state.total_packet_counter = state.total_packet_counter + 1
    state.total_byte_counter = state.total_byte_counter + buf:getSize()

    state.interval_packet_counter = state.interval_packet_counter + 1
    state.interval_byte_counter = state.interval_byte_counter + buf:getSize()

    if flowKey.ethertype == eth.TYPE_PNIO then
        handlePnioPacket(ts, state, buf, isFirstPacket)
    end

    state.last_seen = ts -- Needs to updates last, because this values is need by handlePnioiPacket
end

------------------------------------------------------------------------------------
---- Checker configuration
------------------------------------------------------------------------------------

-- Set the interval in which the checkExpiry function should be called.
module.checkInterval = 5 -- float in seconds

-- Per checker run persistent state, e.g., to track overall flow changes
module.checkState = {}

-- Function that gets called once per checker run at very beginning, before any flow is touched
function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * 10 ^ 6 -- in miro_seconds
end

local function resetFlowState(flow_state, start_time)
    flow_state.interval_start_time = start_time
    flow_state.interval_packet_counter = 0
    flow_state.interval_byte_counter = 0
    flow_state.interval_pnrt_cycle_counter_jitter_max = 0.0
    flow_state.interval_pnrt_out_of_order_counter = 0
    flow_state.interval_pnrt_repetition_counter = 0
    flow_state.interval_pnrt_dropped_counter = 0
end

local function exportFlowState(flow_key, flow_state, current_time)
    local time_delta = tonumber(current_time - (flow_state.interval_start_time / 10 ^ 6)) -- In seconds
    local bytes_per_second = tonumber(flow_state.interval_byte_counter * 8) / time_delta
    local packets_per_second = tonumber(flow_state.interval_packet_counter) / time_delta

    local flow_state_summary = {
        flow_key = flow_key,
        current_time = current_time,
        bytes_per_second = bytes_per_second,
        packets_per_second = packets_per_second,
        flow_state = flow_state
    }
    -- TODO: Somehow export stats to a databse
    print(flow_state_summary)

    resetFlowState(flow_state, current_time * 10 ^ 6)
end

-- Function that gets called in regular intervals to decide if a flow is still active.
-- Returns false for active flows.
-- Returns true and a timestamp in seconds for flows that are expired.
function module.checkExpiry(flow_key, flow_state, check_state)
    local current_time = lm.getTime() -- in seconds

    exportFlowState(flow_key, flow_state, current_time)

    local last_seen_seconds = tonumber(flow_state.last_seen) / 10 ^ 6 -- Convert back to seconds
    if last_seen_seconds + INACTIVE_FLOW_EXPIRY < current_time then
        return true, last_seen_seconds
    end

    return false
end

-- Function that gets called once per checker run at very end, after all flows have been processed
function module.checkFinalizer(checkState, keptFlows, purgedFlows)
    local t = lm.getTime() * 10 ^ 6
    log:info("[Checker]: Done, took %fs, flows %i/%i/%i [purged/kept/total]",
        (t - tonumber(checkState.start_time)) / 10 ^ 6, purgedFlows, keptFlows, purgedFlows + keptFlows)
end

return module

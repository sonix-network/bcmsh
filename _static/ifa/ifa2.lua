-- ifa2.lua - Wireshark dissector for IFA 2.0 (In-band Flow Analyzer),
-- draft-kumar-ippm-ifa, with the Broadcom Trident 3 metadata format
-- (local name space 1, 32 bytes per hop).
--
-- Install: copy to your Wireshark personal Lua plugins folder
-- (Help > About Wireshark > Folders), or run
--   wireshark -X lua_script:ifa2.lua capture.pcap
-- The IP protocol number that marks IFA packets is a preference
-- (Edit > Preferences > Protocols > IFA2, default 253).

local ifa = Proto("ifa2", "In-band Flow Analyzer 2.0")

local gns_names = { [0xF] = "Local name space (per hop)" }
local speed_names = {
  [0] = "10G", [1] = "25G", [2] = "40G", [3] = "50G",
  [4] = "100G", [5] = "200G", [6] = "400G",
}

local f = ifa.fields
f.ver       = ProtoField.uint8("ifa2.version", "Version", base.DEC, nil, 0xF0)
f.gns       = ProtoField.uint8("ifa2.gns", "Global name space", base.HEX, gns_names, 0x0F)
f.nexthdr   = ProtoField.uint8("ifa2.next_header", "Next header", base.DEC)
f.flags     = ProtoField.uint8("ifa2.flags", "Flags", base.HEX)
f.flag_mf   = ProtoField.bool("ifa2.flags.mf", "Metadata fragment", 8, nil, 0x10)
f.flag_ts   = ProtoField.bool("ifa2.flags.ts", "Tail stamp", 8, nil, 0x08)
f.flag_i    = ProtoField.bool("ifa2.flags.inband", "Inband (live traffic)", 8, nil, 0x04)
f.flag_ta   = ProtoField.bool("ifa2.flags.ta", "Turn around", 8, nil, 0x02)
f.flag_c    = ProtoField.bool("ifa2.flags.checksum", "Checksum header present", 8, nil, 0x01)
f.maxlen    = ProtoField.uint8("ifa2.max_length", "Max metadata length (4-byte words)", base.DEC)

f.l4        = ProtoField.bytes("ifa2.l4_header", "Layer 4 header")
f.sport     = ProtoField.uint16("ifa2.udp.srcport", "UDP source port", base.DEC)
f.dport     = ProtoField.uint16("ifa2.udp.dstport", "UDP destination port", base.DEC)
f.ulen      = ProtoField.uint16("ifa2.udp.length", "UDP length", base.DEC)
f.ucsum     = ProtoField.uint16("ifa2.udp.checksum", "UDP checksum", base.HEX)

f.reqvec    = ProtoField.uint8("ifa2.md.request_vector", "Request vector", base.HEX)
f.actvec    = ProtoField.uint8("ifa2.md.action_vector", "Action vector", base.HEX)
f.hoplimit  = ProtoField.uint8("ifa2.md.hop_limit", "Hop limit", base.DEC)
f.curlen    = ProtoField.uint8("ifa2.md.current_length", "Current length (4-byte words)", base.DEC)

f.hop       = ProtoField.bytes("ifa2.hop", "Hop metadata")
f.lns       = ProtoField.uint32("ifa2.hop.lns", "Local name space", base.DEC, nil, 0xF0000000)
f.devid     = ProtoField.uint32("ifa2.hop.device_id", "Device ID", base.HEX, nil, 0x0FFFFF00)
f.ttl       = ProtoField.uint32("ifa2.hop.ip_ttl", "IP TTL", base.DEC, nil, 0x000000FF)
f.speed     = ProtoField.uint32("ifa2.hop.egress_port_speed", "Egress port speed", base.DEC, speed_names, 0xF0000000)
f.cong      = ProtoField.uint32("ifa2.hop.congestion", "Congestion", base.DEC, nil, 0x0C000000)
f.queue     = ProtoField.uint32("ifa2.hop.queue_id", "Queue ID", base.DEC, nil, 0x03F00000)
f.rxsec     = ProtoField.uint32("ifa2.hop.rx_ts_sec", "Rx timestamp, seconds", base.DEC, nil, 0x000FFFFF)
f.egport    = ProtoField.uint16("ifa2.hop.egress_port", "Egress system port", base.DEC)
f.inport    = ProtoField.uint16("ifa2.hop.ingress_port", "Ingress system port", base.DEC)
f.rxns      = ProtoField.uint32("ifa2.hop.rx_ts_ns", "Rx timestamp, nanoseconds", base.DEC)
f.resns     = ProtoField.uint32("ifa2.hop.residence_ns", "Residence time, nanoseconds", base.DEC)
f.opaque    = ProtoField.uint32("ifa2.hop.opaque", "Opaque data", base.HEX)
f.raw       = ProtoField.bytes("ifa2.hop.raw", "Metadata (unknown name space)")

ifa.prefs.ip_proto = Pref.uint("IP protocol", 253, "IP protocol number that marks IFA 2.0 packets")

local data_dis = Dissector.get("data")

local function dissect_hop(buf, tree, n)
  local lns = buf(0, 1):uint() >> 4
  local h = tree:add(f.hop, buf(0, 32))
  if lns ~= 1 then
    h:set_text(string.format("Hop %d: name space %d (not decoded)", n, lns))
    h:add(f.raw, buf(0, 32))
    return
  end
  local dev = (buf(0, 4):uint() >> 8) & 0xFFFFF
  h:set_text(string.format("Hop %d: device 0x%05x, ingress port %d, egress port %d",
                           n, dev, buf(10, 2):uint(), buf(8, 2):uint()))
  h:add(f.lns, buf(0, 4))
  h:add(f.devid, buf(0, 4))
  h:add(f.ttl, buf(0, 4))
  h:add(f.speed, buf(4, 4))
  h:add(f.cong, buf(4, 4))
  h:add(f.queue, buf(4, 4))
  h:add(f.rxsec, buf(4, 4))
  h:add(f.egport, buf(8, 2))
  h:add(f.inport, buf(10, 2))
  h:add(f.rxns, buf(12, 4))
  h:add(f.resns, buf(16, 4))
  for i = 0, 2 do
    h:add(f.opaque, buf(20 + 4 * i, 4))
  end
end

function ifa.dissector(buf, pinfo, tree)
  if buf:len() < 4 then return 0 end
  pinfo.cols.protocol = "IFA2"
  local t = tree:add(ifa, buf(), "In-band Flow Analyzer 2.0")

  local hdr = t:add(buf(0, 4), "IFA header")
  hdr:add(f.ver, buf(0, 1))
  hdr:add(f.gns, buf(0, 1))
  hdr:add(f.nexthdr, buf(1, 1))
  local fl = hdr:add(f.flags, buf(2, 1))
  fl:add(f.flag_mf, buf(2, 1))
  fl:add(f.flag_ts, buf(2, 1))
  fl:add(f.flag_i, buf(2, 1))
  fl:add(f.flag_ta, buf(2, 1))
  fl:add(f.flag_c, buf(2, 1))
  hdr:add(f.maxlen, buf(3, 1))

  local nexthdr = buf(1, 1):uint()
  local off = 4
  local l4len
  if nexthdr == 17 then
    l4len = 8
    local u = t:add(f.l4, buf(off, 8))
    u:set_text("UDP header")
    u:add(f.sport, buf(off, 2))
    u:add(f.dport, buf(off + 2, 2))
    u:add(f.ulen, buf(off + 4, 2))
    u:add(f.ucsum, buf(off + 6, 2))
  elseif nexthdr == 6 then
    l4len = (buf(off + 12, 1):uint() >> 4) * 4
    t:add(f.l4, buf(off, l4len)):set_text(string.format("TCP header (%d bytes)", l4len))
  else
    l4len = 0
  end
  off = off + l4len

  local md = t:add(buf(off, 4), "IFA metadata header")
  md:add(f.reqvec, buf(off, 1))
  md:add(f.actvec, buf(off + 1, 1))
  md:add(f.hoplimit, buf(off + 2, 1))
  md:add(f.curlen, buf(off + 3, 1))
  local words = buf(off + 3, 1):uint()
  off = off + 4

  local stack = t:add(buf(off, words * 4),
                      string.format("Metadata stack (%d bytes, newest hop first)", words * 4))
  local n = 1
  local p = 0
  while p + 32 <= words * 4 do
    dissect_hop(buf(off + p, 32), stack, n)
    p = p + 32
    n = n + 1
  end
  off = off + words * 4
  pinfo.cols.info = string.format("IFA2 %d hop(s), hop limit %d, next header %d",
                                  n - 1, buf(off - words * 4 - 2, 1):uint(), nexthdr)

  if off < buf:len() then
    data_dis:call(buf(off):tvb(), pinfo, tree)
  end
  return buf:len()
end

local registered
local function register()
  local ip = DissectorTable.get("ip.proto")
  if registered then ip:remove(registered, ifa) end
  ip:add(ifa.prefs.ip_proto, ifa)
  registered = ifa.prefs.ip_proto
end
ifa.prefs_changed = register
register()

/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "BGPPrefixSID.h"
#include <typeinfo>

#include <arpa/inet.h>

#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace bgp_msg {

/**
 * Constructor for class
 *
 * \details Handles BGP MP Reach NLRI
 *
 * \param [in]     logPtr                   Pointer to existing Logger for app logging
 * \param [in]     pperAddr                 Printed form of peer address used for logging
 * \param [in]     peer_info                Persistent Peer info pointer
 * \param [in]     enable_debug             Debug true to enable, false to disable
 */
BGPPrefixSID::BGPPrefixSID(Logger *logPtr, std::string peerAddr, BMPReader::peer_info *peer_info, bool enable_debug)
    : debug{enable_debug}, logger{logPtr}, peer_info{peer_info} {
        this->peer_addr = peerAddr;
}

BGPPrefixSID::~BGPPrefixSID() {
}

void BGPPrefixSID::readData(u_char *field, u_char *data, size_t size, bool host_byte_order) {
    int j=0;
    if(host_byte_order){
        for(int i=size-1; i>=0; i--){
            field[j++] = data[i];
        }
    } else {
        for(int i=0; i<size; i++){
            field[j++] = data[i];
        }
    }
}

void BGPPrefixSID::readData(uint16_t *field, u_char *data, size_t size, bool host_byte_order) {
    readData((u_char*)field, data, size, host_byte_order);
}


/**
 * Parse the BGP Prefix-SID attribute data
 *
 * \details
 *      Will parse the BGP Prefix-SID data passed.  Parsed data will be stored
 *      in parsed_data.
 *
 *      \see RFC4760 for format details.
 *
 * \param [in]   attr_len               Length of the attribute data
 * \param [in]   data                   Pointer to the attribute data
 * \param [out]  parsed_data            Reference to parsed_update_data; will be updated with all parsed data
 */
void BGPPrefixSID::parseBGPPrefixSIDAttr(int attr_len, u_char *data, UpdateMsg::parsed_update_data &parsed_data) {

    //SELF_DEBUG("%s: remaining attr_len = %d", peer_addr.c_str(), attr_len);
    boost::property_tree::ptree pt, sub_pt;

    // for each TLV in Attr
    while(attr_len>0){
        bgp_prefix_sid_tlv tlv;
        readData(&tlv.type, data, 1); data++;
        readData(&tlv.len, data, 2); data+=2;
        readData(&tlv.reserved, data, 1); data++;
        //SELF_DEBUG("%s: parsed tlv_len = %d", peer_addr.c_str(), tlv.len);
        int tlv_len = tlv.len-1;
        
        switch(tlv.type){
            case BGP_PREFIX_SID_TLV_TYPE_SRV6_L3_SERVICE_TLV: {
                SELF_DEBUG("%s: BGP_PREFIX_SID_TLV_TYPE_SRV6_L3_SERVICE_TLV:", peer_addr.c_str());
                sub_pt = parseSRv6L3ServiceTLV(tlv_len, data);
                pt.add_child("srv6_l3_service", sub_pt);
                break;
            }
            default:
                SELF_DEBUG("%s: BGP Prefix SID Attr TLV type %d is not yet implemented or intentionally ignored, skipping for now.",
                        peer_addr.c_str(), tlv.type);
                break;
        }
        attr_len -= (tlv.len+3);
        //SELF_DEBUG("%s: remaining attr_len = %d", peer_addr.c_str(), attr_len);
        data += (tlv.len-1);
    }
    parsed_data.attr_prefix_sid = pt;
}

boost::property_tree::ptree BGPPrefixSID::parseSRv6L3ServiceTLV(int tlv_len, u_char *data){
    //SELF_DEBUG("%s: Start to parse SRv6 L3 Service TLV with length %d", peer_addr.c_str(), tlv_len);
    boost::property_tree::ptree pt;
    int tlv_cnt = 0;
    //SELF_DEBUG("%s: remaining tlv_len for subtlvs = %d", peer_addr.c_str(), tlv_len);
    while(tlv_len){
        srv6_service_sub_tlv subtlv;
        readData(&subtlv.type, data, 1); data++;
        readData(&subtlv.len, data, 2); data+=2;
        //SELF_DEBUG("%s: parsed subtlv_len = %d", peer_addr.c_str(), subtlv.len);
        readData(&subtlv.reserved, data, 1); data++;
        
        //SELF_DEBUG("%s: sub-TLV type %d with length %d", peer_addr.c_str(), subtlv.type, subtlv.len);

        u_char *sub_data = data;
        boost::property_tree::ptree sub_pt;

        switch(subtlv.type){
            case SRV6_SID_INFORMATION_SUB_TLV: {
                SELF_DEBUG("%s:  SRV6_SID_INFORMATION_SUB_TLV:", peer_addr.c_str());
                srv6_sid_information_sub_tlv srv6_sid_information;
                
                readData(srv6_sid_information.sid_value, sub_data, 16, false); sub_data+=16;
                readData(&srv6_sid_information.service_sid_flags, sub_data, 1); sub_data++;
                readData(&srv6_sid_information.endpoint_behavior, sub_data, 2); sub_data+=2;
                readData(&srv6_sid_information.reserved, sub_data, 1); sub_data++;

                char sid_char[40];
                inet_ntop(AF_INET6, srv6_sid_information.sid_value, sid_char, sizeof(sid_char));
                sub_pt.put("sid_value", std::string(sid_char));
                sub_pt.put("service_sid_flags", srv6_sid_information.service_sid_flags);
                sub_pt.put("endpoint_behavior_codepoint", srv6_sid_information.endpoint_behavior);
                sub_pt.put("endpoint_behavior", std::string(endpoint_behavior_codepoint_to_name(srv6_sid_information.endpoint_behavior)));
                
                int subtlv_len = subtlv.len-21;
                SELF_DEBUG("%s:   SID Value = %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                                peer_addr.c_str(), 
                                srv6_sid_information.sid_value[0],  srv6_sid_information.sid_value[1],
                                srv6_sid_information.sid_value[2],  srv6_sid_information.sid_value[3],
                                srv6_sid_information.sid_value[4],  srv6_sid_information.sid_value[5],
                                srv6_sid_information.sid_value[6],  srv6_sid_information.sid_value[7],
                                srv6_sid_information.sid_value[8],  srv6_sid_information.sid_value[9],
                                srv6_sid_information.sid_value[10], srv6_sid_information.sid_value[11],
                                srv6_sid_information.sid_value[12], srv6_sid_information.sid_value[13],
                                srv6_sid_information.sid_value[14], srv6_sid_information.sid_value[15]
                                );
                SELF_DEBUG("%s:   SID Flags = %02X",
                    peer_addr.c_str(), srv6_sid_information.service_sid_flags);
                SELF_DEBUG("%s:   Endpoint Behavior = %d", 
                    peer_addr.c_str(), std::string(endpoint_behavior_codepoint_to_name(srv6_sid_information.endpoint_behavior)));
                int subtlv_cnt = 0;
                //SELF_DEBUG("%s: remaining subtlv_len for subsubtlvs = %d", peer_addr.c_str(), subtlv_len);
                while(subtlv_len>0){
                    srv6_service_data_sub_sub_tlv subsubtlv;
                    readData(&subsubtlv.type, sub_data, 1); sub_data++;
                    readData(&subsubtlv.len, sub_data, 2); sub_data+=2;
                    //SELF_DEBUG("%s: parsed subsubtlv_len = %d", peer_addr.c_str(), subsubtlv.len);
                    readData(&subsubtlv.reserved, sub_data, 1); sub_data++;
                    u_char *subsub_data = sub_data;
                    boost::property_tree::ptree subsub_pt;
                    switch(subsubtlv.type){
                        case SRV6_SID_STRUCTURE_SUB_SUB_TLV: {
                             SELF_DEBUG("%s:    SRV6_SID_STRUCTURE_SUB_SUB_TLV:",
                                    peer_addr.c_str());
                            srv6_sid_information.sid_structure.locator_block_length = *subsub_data++;
                            srv6_sid_information.sid_structure.locator_node_length = *subsub_data++;
                            srv6_sid_information.sid_structure.function_length = *subsub_data++;
                            srv6_sid_information.sid_structure.argument_length = *subsub_data++;
                            srv6_sid_information.sid_structure.transposition_length = *subsub_data++;
                            srv6_sid_information.sid_structure.transposition_offset = *subsub_data++;
                            SELF_DEBUG("%s:     locator_block_length = %d", peer_addr.c_str(), srv6_sid_information.sid_structure.locator_block_length);
                            SELF_DEBUG("%s:     locator_node_length = %d", peer_addr.c_str(), srv6_sid_information.sid_structure.locator_node_length);
                            SELF_DEBUG("%s:     function_length = %d", peer_addr.c_str(), srv6_sid_information.sid_structure.function_length);
                            SELF_DEBUG("%s:     argument_length = %d", peer_addr.c_str(), srv6_sid_information.sid_structure.argument_length);
                            SELF_DEBUG("%s:     transposition_length = %d", peer_addr.c_str(), srv6_sid_information.sid_structure.transposition_length);
                            SELF_DEBUG("%s:     transposition_offset = %d", peer_addr.c_str(), srv6_sid_information.sid_structure.transposition_offset);
                            subsub_pt.put("locator_block_length", srv6_sid_information.sid_structure.locator_block_length);
                            subsub_pt.put("locator_node_length", srv6_sid_information.sid_structure.locator_node_length);
                            subsub_pt.put("function_length", srv6_sid_information.sid_structure.function_length);
                            subsub_pt.put("argument_length", srv6_sid_information.sid_structure.argument_length);
                            subsub_pt.put("transposition_length", srv6_sid_information.sid_structure.transposition_length);
                            subsub_pt.put("transposition_offset", srv6_sid_information.sid_structure.transposition_offset);
                            sub_pt.add_child("sid_structure", subsub_pt);
                            break;
                        }
                        default:
                            SELF_DEBUG("%s: Sub-Sub-TLV for SRv6 SID Information Sub-TLV type %d is not yet implemented or intentionally ignored, skipping for now.",
                                peer_addr.c_str(), subsubtlv.type);
                            break;
                    }
                    sub_data += (subsubtlv.len-1);
                    //SELF_DEBUG("%s: parsed %d bytes for this subsubtlv", peer_addr.c_str(), subsubtlv.len+3);
                    subtlv_len -= (subsubtlv.len+3);
                    //SELF_DEBUG("%s: remaining subtlv_len = %d", peer_addr.c_str(), subtlv_len);
                    if(++subtlv_cnt>3){
                        if(++tlv_cnt>3){
                            SELF_DEBUG("%s: Too much loop in Sub-tlv", peer_addr.c_str());
                            break;
                        }
                    }
                }
                pt.add_child("sid_information", sub_pt);
                break;
            }
            default:
                SELF_DEBUG("%s: Sub-TLV for SRv6 L3 Service TLV type %d is not yet implemented or intentionally ignored, skipping for now.",
                        peer_addr.c_str(), subtlv.type);
                break;
        }
        data += (subtlv.len-1);
        //SELF_DEBUG("%s: parsed %d bytes for this subtlv", peer_addr.c_str(),subtlv.len+3);
        tlv_len -= (subtlv.len+3);
        //SELF_DEBUG("%s: remaining  tlv_len = %d", peer_addr.c_str(), tlv_len);
        if(++tlv_cnt>3){
            SELF_DEBUG("%s: Too much loop in tlv", peer_addr.c_str());
            break;
        }
    }
    return pt;
}

} /* namespace bgp_msg */

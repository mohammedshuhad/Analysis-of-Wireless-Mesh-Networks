//
//  wmn_analysis.hpp
//  
//
//  Course : ENSC 833 (Network Protocols), 
//  Final Project : Analysiss of Wireless Mesh Networks
//  Group 4 : Mohammed Shuhad and Mary Joseph 
//  Created on : 21/03/22.
//

#ifndef wmn_analysis_hpp
#define wmn_analysis_hpp

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mesh-module.h"
#include "ns3/mobility-module.h"
#include "ns3/mesh-helper.h"
#include "ns3/flow-monitor-module.h"
#include <iomanip>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ns3/flow-monitor-helper.h>
#include "ns3/gnuplot.h"
#include "ns3/netanim-module.h"
#include "ns3/point-to-point-module.h" //MJ
#include "ns3/csma-helper.h" //MJ
#include "ns3/olsr-helper.h" //shd
#include "ns3/aodv-helper.h" //shd
#include "ns3/dsdv-helper.h" //shd
#include "ns3/dsr-helper.h" //shd
#include "ns3/dsr-main-helper.h" //shd
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/packet-metadata.h" //MJ
#include <iostream>
#include <sstream>
#include <fstream>
using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("infrastructure-mesh");
void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon, Gnuplot2dDataset DataSet);
// Method for setting mobility using (x,y) position for the nodes
static void
SetPosition (Ptr<Node> node, double x, double y);
class MeshExperiment
{
public:
    MeshExperiment();
    int Run();
private:
enum RoutingProt { OLSR, AODV, DSDV };
    int m_xSize;
    int m_ySize;
    double m_step;
    double m_randomStart;
    double m_totalTime;
    double m_packetInterval;
    uint16_t m_packetSize;
    uint32_t m_nIfaces;
    bool m_chan;
    bool m_pcap;
    std::string m_stack;
    std::string m_phyMode;
    std::string m_rate;
    std::string m_root;
    /// NodeContainer for individual nodes
    NodeContainer nc_sta1, nc_sta2;
    NodeContainer nc_ap1, nc_ap2;
    NodeContainer nc_mr1, nc_mr2;
    NodeContainer nc_mbb1, nc_mbb2;
    NodeContainer nc_gw1, nc_gw2;
    NodeContainer nc_bb1;
    // NodeContainer for categorical nodes
    NodeContainer nc_sta, nc_ap, nc_mesh1, nc_mesh2;
    // NodeContainer for connected nodes
    // shd NodeContainer nc_sta1Ap1, nc_sta2Ap2;
    NodeContainer nc_ap1Mr1, nc_ap2Mr2;
    // shd NodeContainer nc_mr1Mbb1, nc_mr2Mbb2;
    // shd NodeContainer nc_mbb1Gw1, nc_mbb2Gw2;
    NodeContainer nc_gw1Bb1, nc_gw2Bb1;

    // List of categorical NetDevice Container
    NetDeviceContainer de_sta1, de_sta2;
    NetDeviceContainer de_ap1, de_ap2;
    // List of WiFi NetDevice Container
    NetDeviceContainer de_wifi_sta1Ap1;
    NetDeviceContainer de_wifi_sta2Ap2;
    // List of mesh NetDevice Container
    NetDeviceContainer de_mesh1;
    NetDeviceContainer de_mesh2;
    // shd NetDeviceContainer de_mesh_mbb1Gw1;
    // shd NetDeviceContainer de_mesh_mbb2Gw2;
    // shd NetDeviceContainer de_mesh_mr1Mbb1;
    // shd NetDeviceContainer de_mesh_mr2Mbb2;
    // List of CSMA NetDevice Container
    NetDeviceContainer de_csma_ap1Mr1;
    NetDeviceContainer de_csma_ap2Mr2;
    // List of p2p NetDevice Container
    NetDeviceContainer de_p2p_gw1Bb1;
    NetDeviceContainer de_p2p_gw2Bb1;
    // List of interface container
    Ipv4InterfaceContainer if_wifi_sta1Ap1;
    Ipv4InterfaceContainer if_wifi_sta2Ap2;
    // shd Ipv4InterfaceContainer if_mesh_mr1Mbb1;
    // shd Ipv4InterfaceContainer if_mesh_mr2Mbb2;
    Ipv4InterfaceContainer if_mesh1;
    Ipv4InterfaceContainer if_mesh2;
    Ipv4InterfaceContainer if_csma_ap1Mr1;
    Ipv4InterfaceContainer if_csma_ap2Mr2;
    Ipv4InterfaceContainer if_p2p_gw1Bb1;
    Ipv4InterfaceContainer if_p2p_gw2Bb1;
    // Helper
    MeshHelper meshHelper1, meshHelper2;
    PointToPointHelper p2pHelper;
    CsmaHelper csmaHelper;
    Ipv4AddressHelper address;
    
    void SetupChannels();
    void CreateNodes();
    void InstallInternetStack(RoutingProt prot);
    void SetupMobility();
    void InstallApplication();
    void Report();
};

#endif /* wmn_analysis_hpp */

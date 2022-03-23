//
//  wmn_analysis.cpp
//  
//
//  Course : ENSC 833 (Network Protocols), 
//  Final Project : Analysiss of Wireless Mesh Networks
//  Group 4 : Mohammed Shuhad and Mary Joseph 
//  Created on : 21/03/22.
//

#include "wmn_analysis.hpp"
static void
SetPosition (Ptr<Node> node, double x, double y)
{
  Ptr<MobilityModel> mobility = node->GetObject<MobilityModel> ();
  Vector pos = mobility->GetPosition ();
  pos.x = x;
  pos.y = y;
  mobility->SetPosition (pos);
}

MeshExperiment::MeshExperiment () :
m_xSize (2),
m_ySize (2),
m_step (40.0),
m_randomStart (0.1),
m_totalTime (40.0),
m_packetInterval (1.0),
m_packetSize (1024),
m_nIfaces (1),
m_chan (true),
m_pcap (false),
m_stack ("ns3::Dot11sStack"),
m_phyMode ("DsssRate1Mbps"),
m_rate ("8kbps"),
m_root ("ff:ff:ff:ff:ff:ff")
{
    Config::SetDefault ("ns3::OnOffApplication::DataRate",
                        StringValue (m_rate));
}

void MeshExperiment::SetupChannels()
{
    // Create p2p links between backbone (bb1) and gateways (gw1, gw2)
  p2pHelper.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2pHelper.SetChannelAttribute ("Delay", StringValue ("10ms"));
  de_p2p_gw1Bb1 = p2pHelper.Install (nc_gw1Bb1);
  de_p2p_gw2Bb1 = p2pHelper.Install (nc_gw2Bb1);
  
  // Create CSMA connection between MRs (mr1, mr2) and APs (ap1, ap2)
  csmaHelper.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
  de_csma_ap1Mr1 = csmaHelper.Install (nc_ap1Mr1);
  de_csma_ap2Mr2 = csmaHelper.Install (nc_ap2Mr2);
  // Configure YansWifiChannel
  //MJ YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiPhyHelper wifiPhy; //MJ
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());
  //------------------------ mesh router1 -----------------------------------
  /*
   * Create mesh helper and set stack installer to it
   * Stack installer creates all needed protocols and install them to
   * mesh point device
   */
  meshHelper1 = MeshHelper::Default ();
  if (!Mac48Address (m_root.c_str ()).IsBroadcast ())
    {
      meshHelper1.SetStackInstaller (m_stack, "Root", Mac48AddressValue (Mac48Address (m_root.c_str ())));
    }
  else
    {
      //If root is not set, we do not use "Root" attribute, because it
      //is specified only for 11s
      meshHelper1.SetStackInstaller (m_stack);
    }
  if (m_chan)
    {
      meshHelper1.SetSpreadInterfaceChannels (MeshHelper::SPREAD_CHANNELS);
    }
  else
    {
      meshHelper1.SetSpreadInterfaceChannels (MeshHelper::ZERO_CHANNEL);
    }
  meshHelper1.SetMacType ("RandomStart", TimeValue (Seconds (m_randomStart)));
  // Set number of interfaces - default is single-interface mesh point
  meshHelper1.SetNumberOfInterfaces (m_nIfaces);
  // Install protocols and return container if MeshPointDevices
  de_mesh1 = meshHelper1.Install (wifiPhy, nc_mesh1);

  //----------------------mesh router2 ------------------------------------------
  meshHelper2 = MeshHelper::Default ();
  if (!Mac48Address (m_root.c_str ()).IsBroadcast ())
    {
      meshHelper2.SetStackInstaller (m_stack, "Root", Mac48AddressValue (Mac48Address (m_root.c_str ())));
    }
  else
    {
      //If root is not set, we do not use "Root" attribute, because it
      //is specified only for 11s
      meshHelper2.SetStackInstaller (m_stack);
    }
  if (m_chan)
    {
      meshHelper2.SetSpreadInterfaceChannels (MeshHelper::SPREAD_CHANNELS);
    }
  else
    {
      meshHelper2.SetSpreadInterfaceChannels (MeshHelper::ZERO_CHANNEL);
    }
  meshHelper2.SetMacType ("RandomStart", TimeValue (Seconds (m_randomStart)));
  // Set number of interfaces - default is single-interface mesh point
  meshHelper2.SetNumberOfInterfaces (m_nIfaces);
  de_mesh2 = meshHelper2.Install (wifiPhy, nc_mesh2);

   // TODO: Setup Mobility for mesh nodes
  
  
  // Setup WiFi for network 1
  //MJ WifiHelper wifi1 = WifiHelper::Default ();
  WifiHelper wifi1; //MJ
  
  //MJ wifi1.SetStandard (WIFI_PHY_STANDARD_80211b);
  wifi1.SetStandard (WIFI_STANDARD_80211b); //MJ
  
  wifi1.SetRemoteStationManager ("ns3::AarfWifiManager");
  //MJ NqosWifiMacHelper mac1 = NqosWifiMacHelper::Default ();
  WifiMacHelper mac1; //MJ
  
  wifi1.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue (m_phyMode),
                                 "ControlMode", StringValue (m_phyMode));
  // TODO: Change SSID for different networks
  // Install on different ap1 <--> sta1, ap2 <--> sta2
  // STA1 and AP1 are initialized for network 1
  Ssid ssid1 = Ssid ("network-1");
  mac1.SetType ("ns3::StaWifiMac",
                "Ssid", SsidValue (ssid1),
                "ActiveProbing", BooleanValue (true));
  de_sta1 = wifi1.Install (wifiPhy, mac1, nc_sta1);
  // Setup AP for network 1
  mac1.SetType ("ns3::ApWifiMac",
                "Ssid", SsidValue (ssid1));
  de_ap1 = wifi1.Install (wifiPhy, mac1, nc_ap1);
  
  // Setup WiFi for network 2
  //MJ WifiHelper wifi2 = WifiHelper::Default ();
  WifiHelper wifi2; //MJ
  
  //MJ wifi2.SetStandard (WIFI_PHY_STANDARD_80211b);
  wifi2.SetStandard (WIFI_STANDARD_80211b); //MJ
  
  wifi2.SetRemoteStationManager ("ns3::AarfWifiManager");
  //MJ NqosWifiMacHelper mac2 = NqosWifiMacHelper::Default ();
  WifiMacHelper mac2; //MJ
  
  wifi2.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue (m_phyMode),
                                 "ControlMode", StringValue (m_phyMode));
  // STA and APs are initialized for network 2
  Ssid ssid2 = Ssid ("network-2");
  mac2.SetType ("ns3::StaWifiMac",
                "Ssid", SsidValue (ssid2),
                "ActiveProbing", BooleanValue (true));
  de_sta2 = wifi2.Install (wifiPhy, mac2, nc_sta2);
  // Setup AP for network 2
  mac2.SetType ("ns3::ApWifiMac",
                "Ssid", SsidValue (ssid2));
  de_ap2 = wifi2.Install (wifiPhy, mac2, nc_ap2);
  // Net Device container for STA and AP in network 1
  de_wifi_sta1Ap1.Add (de_sta1);
  de_wifi_sta1Ap1.Add (de_ap1);
  // Net Device container for STA and AP in network 2
  de_wifi_sta2Ap2.Add (de_sta2);
  de_wifi_sta2Ap2.Add (de_ap2);
}
void
MeshExperiment::CreateNodes ()
{
  // Create individual nodes in their node container
  nc_sta1.Create (1);
  nc_sta2.Create (1);
  nc_ap1.Create (1);
  nc_ap2.Create (1);
  nc_mr1.Create (1);
  nc_mr2.Create (1);
  nc_mbb1.Create (m_ySize * m_xSize);
  nc_mbb2.Create (m_ySize * m_xSize);
  nc_gw1.Create (1);
  nc_gw2.Create (1);
  nc_bb1.Create (1);
  // Create categorical Node Container
  // shd nc_sta = NodeContainer (nc_sta1, nc_sta2);
  // shd nc_ap = NodeContainer (nc_ap1, nc_ap2);
  // Create connected nodes in their node container
  // shd nc_sta1Ap1 = NodeContainer (nc_sta1, nc_ap1);
  // shd nc_sta2Ap2 = NodeContainer (nc_sta2, nc_ap2);
  nc_ap1Mr1 = NodeContainer (nc_ap1, nc_mr1);
  nc_ap2Mr2 = NodeContainer (nc_ap2, nc_mr2);
  // shd nc_mr1Mbb1 = NodeContainer (nc_mr1, nc_mbb1);
  // shd nc_mr2Mbb2 = NodeContainer (nc_mr2, nc_mbb2);
  // shd nc_mbb1Gw1 = NodeContainer (nc_mbb1, nc_gw1);
  // shd nc_mbb2Gw2 = NodeContainer (nc_mbb2, nc_gw2);
  nc_gw1Bb1 = NodeContainer (nc_gw1, nc_bb1);
  nc_gw2Bb1 = NodeContainer (nc_gw2, nc_bb1);
  nc_mesh1 = NodeContainer (nc_mr1, nc_mbb1, nc_gw1);
  nc_mesh2 = NodeContainer (nc_mr2, nc_mbb2, nc_gw2);
}
void
MeshExperiment::SetupMobility ()
{
  // Setup mobility for the nodes
  MobilityHelper fixedMobility;
  fixedMobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                      "MinX", DoubleValue (0.0),
                                      "MinY", DoubleValue (((m_xSize - 1) * m_step) / 2),
                                      "DeltaX", DoubleValue (m_step),
                                      "DeltaY", DoubleValue (m_step),
                                      "GridWidth", UintegerValue (5),
                                      "LayoutType", StringValue ("RowFirst"));
  fixedMobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                                  "Bounds", RectangleValue (Rectangle (-75, 75, -75, 75)),
                                  "Speed", StringValue ("ns3::UniformRandomVariable[Min=20.0|Max=50.0]"),
                                  "Direction",StringValue ("ns3::UniformRandomVariable[Min=10.0|Max=26.283184]"));
  fixedMobility.Install (nc_sta1);
  fixedMobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  //fixedMobility.Install(nc_sta1);
  fixedMobility.Install (nc_ap1);
  fixedMobility.Install (nc_mr1);
  fixedMobility.Install (nc_gw1);
  fixedMobility.Install (nc_bb1);
  // -------------------------------Setup mobility for the nodes---------------------
  MobilityHelper fixedMobility2;
  fixedMobility2.SetPositionAllocator ("ns3::GridPositionAllocator",
                                       "MinX", DoubleValue ((3 * m_step)-(m_step / 2)),
                                       "MinY", DoubleValue (0.0),
                                       "DeltaX", DoubleValue (m_step / 2),
                                       "DeltaY", DoubleValue (m_step),
                                       "GridWidth", UintegerValue (m_xSize),
                                       "LayoutType", StringValue ("RowFirst"));
  fixedMobility2.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  // ------------------------Setup fixed position for the network nodes----------------
  fixedMobility2.Install (nc_mbb1);
  MobilityHelper fixedMobility3;
  fixedMobility3.SetPositionAllocator ("ns3::GridPositionAllocator",
                                       "MinX", DoubleValue (0.0),
                                       "MinY", DoubleValue ((((m_xSize - 1) * m_step) + m_step)+(((m_xSize - 1) * m_step))),
                                       "DeltaX", DoubleValue (m_step),
                                       "DeltaY", DoubleValue (m_step),
                                       "GridWidth", UintegerValue (5),
                                       "LayoutType", StringValue ("RowFirst"));
  fixedMobility3.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                                   "Bounds", RectangleValue (Rectangle (-250, 250, -250, 250)),
                                   "Speed", StringValue ("ns3::UniformRandomVariable[Min=10.0|Max=25.0]"),
                                   "Direction",StringValue ("ns3::UniformRandomVariable[Min=10.0|Max=26.283184]"));
  
  fixedMobility3.Install (nc_sta2);
  fixedMobility3.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  // Setup fixed position for the network nodes
  //fixedMobility3.Install(nc_sta2);
  fixedMobility3.Install (nc_ap2);
  fixedMobility3.Install (nc_mr2);
  fixedMobility3.Install (nc_gw2);
  MobilityHelper fixedMobility4;
  fixedMobility4.SetPositionAllocator ("ns3::GridPositionAllocator",
                                       "MinX", DoubleValue ((3 * m_step)-(m_step / 2)),
                                       "MinY", DoubleValue (((((m_xSize - 1) * m_step) / 2)*3) + m_step),
                                       "DeltaX", DoubleValue (m_step / 2),
                                       "DeltaY", DoubleValue (m_step),
                                       "GridWidth", UintegerValue (m_xSize),
                                       "LayoutType", StringValue ("RowFirst"));
  fixedMobility4.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  fixedMobility4.Install (nc_mbb2);
  // possition for bb1, gw1, gw2
  int m_x = ((2 + m_xSize) * m_step) +(2 * m_step);
  int m_y = ((m_xSize * 2) * m_step) / 2;
  SetPosition (nc_bb1.Get (0), m_x, m_y);
  SetPosition (nc_gw1.Get (0), ((m_xSize + 2) * m_step) - m_step, (((m_xSize - 1) * m_step) / 2));
  SetPosition (nc_gw2.Get (0), ((m_xSize + 2) * m_step) - m_step, ((((m_xSize - 1) * m_step) + m_step)+(((m_xSize - 1) * m_step))));
//  SetPosition(nc_gw1.Get(0), 150, 20);
//  SetPosition(nc_gw2.Get(0), 150, 120);
  
  // Setup mobility for the STA1 node
  double startTime = 20.0;
  for (int sta1_x = 0, sta1_y = 0; sta1_y >= -15; sta1_x++, sta1_y -= 3)
    {
      // Change position of STA1 after startTime
      Simulator::Schedule (Seconds (startTime), &SetPosition, nc_sta1.Get (0), sta1_x, sta1_y);
      startTime++;
    }
  // Position STA1 node from AP1 network to AP2 network
  //Simulator::Schedule (Seconds (20.0), &SetPosition, nc_sta1.Get (0), 10.0, 15.0);
  // Position STA2 node from AP2 network to AP2 network
  //Simulator::Schedule (Seconds (20.0), &SetPosition, nc_sta2.Get (0), 0.0, 0.0);
}
void
MeshExperiment::InstallInternetStack (RoutingProt protocol)
{
  InternetStackHelper internetStackHelper;
  OlsrHelper olsrHelper;
  AodvHelper aodvHelper;
  DsdvHelper dsdvHelper;

  switch(protocol)
  {
    case OLSR  : internetStackHelper.SetRoutingHelper (olsrHelper);   break;
    case AODV: internetStackHelper.SetRoutingHelper (aodvHelper); break;
    case DSDV : internetStackHelper.SetRoutingHelper (dsdvHelper); break;
    default : std::cout << "Unrecognized routing\n"; break;
    }

  internetStackHelper.Install (nc_sta1);
  internetStackHelper.Install (nc_sta2);
  internetStackHelper.Install (nc_ap1);
  internetStackHelper.Install (nc_ap2);
  internetStackHelper.Install (nc_mr1);
  internetStackHelper.Install (nc_mr2);
  internetStackHelper.Install (nc_mbb1);
  internetStackHelper.Install (nc_mbb2);
  internetStackHelper.Install (nc_gw1);
  internetStackHelper.Install (nc_gw2);
  internetStackHelper.Install (nc_bb1);

  // Network 1 (left)
  address.SetBase ("10.1.1.0", "255.255.255.0");
  if_wifi_sta1Ap1 = address.Assign (de_wifi_sta1Ap1);
  address.SetBase ("10.1.2.0", "255.255.255.0");
  if_csma_ap1Mr1 = address.Assign (de_csma_ap1Mr1);
  address.SetBase ("10.1.3.0", "255.255.255.0");
  if_mesh1 = address.Assign (de_mesh1);
  address.SetBase ("10.1.4.0", "255.255.255.0");
  if_p2p_gw1Bb1 = address.Assign (de_p2p_gw1Bb1);
  // Network 2 (right)
  address.SetBase ("20.1.1.0", "255.255.255.0");
  if_wifi_sta2Ap2 = address.Assign (de_wifi_sta2Ap2);
  address.SetBase ("20.1.2.0", "255.255.255.0");
  if_csma_ap2Mr2 = address.Assign (de_csma_ap2Mr2);
  address.SetBase ("20.1.3.0", "255.255.255.0");
  if_mesh2 = address.Assign (de_mesh2);
  address.SetBase ("20.1.4.0", "255.255.255.0");
  if_p2p_gw2Bb1 = address.Assign (de_p2p_gw2Bb1);
}
void
MeshExperiment::InstallApplication ()
{
  // Server is set on STA2 in network 2 (right)
  UdpEchoServerHelper echoServer (9);
  ApplicationContainer serverApps = echoServer.Install (nc_sta2.Get (0));
  serverApps.Start (Seconds (0.0));
  serverApps.Stop (Seconds (m_totalTime));
  // Client is set on STA1 in network 1 (left)
  UdpEchoClientHelper echoClient (if_wifi_sta2Ap2.GetAddress (0), 9);
  echoClient.SetAttribute ("MaxPackets", UintegerValue ((uint32_t) (m_totalTime * (1 / m_packetInterval))));
  echoClient.SetAttribute ("Interval", TimeValue (Seconds (m_packetInterval)));
  echoClient.SetAttribute ("PacketSize", UintegerValue (m_packetSize));
  ApplicationContainer clientApps = echoClient.Install (nc_sta1.Get (0));
  clientApps.Start (Seconds (0.0));
  clientApps.Stop (Seconds (m_totalTime));
  //Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
}
int
MeshExperiment::Run ()
{
  CreateNodes ();
  SetupChannels();
  InstallInternetStack (OLSR);
  SetupMobility ();
  InstallApplication ();
  //Gnuplot parameters
  std::string fileNameWithNoExtension = "FlowVSThroughput_ft_";
  std::string graphicsFileName = fileNameWithNoExtension + ".png";
  std::string plotFileName = fileNameWithNoExtension + ".plt";
  std::string plotTitle = "Flow vs Throughput";
  std::string dataTitle = "Throughput";
  // Instantiate the plot and set its title.
  Gnuplot gnuplot (graphicsFileName);
  gnuplot.SetTitle (plotTitle);
  // Make the graphics file, which the plot file will be when it
  // is used with Gnuplot, be a PNG file.
  gnuplot.SetTerminal ("png");
  // Set the labels for each axis.
  gnuplot.SetLegend ("Flow", "Throughput");
  Gnuplot2dDataset dataset;
  dataset.SetTitle (dataTitle);
  dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);
  //flowMonitor declaration
  FlowMonitorHelper fmHelper;
  Ptr<FlowMonitor> allMon = fmHelper.InstallAll ();
  // call the flow monitor function
  ThroughputMonitor (&fmHelper, allMon, dataset);
  Simulator::Stop (Seconds (m_totalTime));
  // Enable graphical interface for netanim
  AnimationInterface animation ("infrastructure-mesh-backbone.xml");
  animation.EnablePacketMetadata (false);
  Simulator::Run ();
  //Gnuplot ...continued
  gnuplot.AddDataset (dataset);
  // Open the plot file.
  std::ofstream plotFile (plotFileName.c_str ());
  // Write the plot file.
  gnuplot.GenerateOutput (plotFile);
  // Close the plot file.
  plotFile.close ();
  Simulator::Destroy ();
  return 0;
}
void
ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon, Gnuplot2dDataset DataSet)
{
  double localThrou = 0;
  std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMon->GetFlowStats ();
  Ptr<Ipv4FlowClassifier> classing = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier ());
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
    {
      Ipv4FlowClassifier::FiveTuple fiveTuple = classing->FindFlow (stats->first);
      std::cout << "Flow ID     : " << stats->first << " ; " << fiveTuple.sourceAddress << " -----> " << fiveTuple.destinationAddress << std::endl;
      std::cout << "Tx Packets = " << stats->second.txPackets << std::endl;
      std::cout << "Rx Packets = " << stats->second.rxPackets << std::endl;
      std::cout << "Duration    : " << (stats->second.timeLastRxPacket.GetSeconds () - stats->second.timeFirstTxPacket.GetSeconds ()) << std::endl;
      std::cout << "Last Received Packet  : " << stats->second.timeLastRxPacket.GetSeconds () << " Seconds" << std::endl;
      std::cout << "Throughput: " << stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds () - stats->second.timeFirstTxPacket.GetSeconds ()) / 1024 / 1024 << " Mbps" << std::endl;
      localThrou = (stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds () - stats->second.timeFirstTxPacket.GetSeconds ()) / 1024 / 1024);
      // updata gnuplot data
      DataSet.Add ((double) Simulator::Now ().GetSeconds (), (double) localThrou);
      std::cout << "---------------------------------------------------------------------------" << std::endl;
    }
  Simulator::Schedule (Seconds (1), &ThroughputMonitor, fmhelper, flowMon, DataSet);
  //if(flowToXml)
  {
    flowMon->SerializeToXmlFile ("infrastructure-mesh-backbone-throughputMonitor.xml", true, true);
  }
}
int
main (int argc, char *argv[])
{
  ns3::PacketMetadata::Enable ();
  LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);
  MeshExperiment t;
  // shd t.Configure (argc, argv);
  return t.Run ();
}

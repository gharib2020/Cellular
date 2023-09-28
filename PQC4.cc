/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 *   Copyright (c) 2019 Centre Tecnologic de Telecomunicacions de Catalunya (CTTC)
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as
 *   published by the Free Software Foundation;
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/**
 *
 * \file PQC4 based on \file cttc-3gpp-channel-nums-fdm.cc of nr package
 * \ingroup examples
 * \brief the full implementation of the distributed mutual authentication process of PQC4: PQC-based Cellular Communication for Critical-Missions in Zero-Trust Environments 
 * In this implementation the variable k represents the degree of distibuted verification, and it is the number of UEs required to cooperate for certificate verification
 *
 * The example implement the PQC4 handshake under multiple loads of gaming, voice 
 * and video traffic. The distributed 
 * It is showing how to configure multiple bandwidth parts, in which
 * some of them form a FDD configuration, while others uses TDD. The user
 * can configure the bandwidth and the frequency of these BWPs. Three types
 * of traffic are available: two are DL (video and voice) while one is
 * UL (gaming). Each traffic will be routed to different BWP. Voice will go
 * in the TDD BWP, while video will go in the FDD-DL one, and gaming in the
 * FDD-UL one.
 * CC or component carrier is the aggregated carrier. The component carrier can have a bandwidth of
 * 1.4,3,5, 10, 15 or 20 MHz and a maximum of five component carriers can be aggregated, hence the
 * maximum aggregated bandwidth is 100 MHz.
 *
 * The configured spectrum division is the following:
\verbatim
    |------------BandTdd--------------|--------------BandFdd---------------|
    |------------CC0------------------|--------------CC1-------------------|
    |------------BWP0-----------------|------BWP1-------|-------BWP2-------|
\endverbatim
 * We will configure BWP0 as TDD, BWP1 as FDD-DL, BWP2 as FDD-UL.
 */

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/config-store.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/netanim-module.h"

using namespace std;
using namespace ns3;

NS_LOG_COMPONENT_DEFINE("3gppChannelNumsFdm");

int64_t randomStream = 1;
Ptr<NrHelper> nrHelper;
static Ipv4InterfaceContainer ueIpIface;
static Ipv4InterfaceContainer internetIpIfaces;
static NodeContainer ueNodes;
static NodeContainer gnbNodes;
static NodeContainer remoteHostContainer;
static Ptr<Node> pgw;
static Ptr<Node> remoteHost;
static MobilityHelper mobilityGnbs;
static MobilityHelper mobilityUEs;
static MobilityHelper mobilityOtherNodes;
static int nodeSpeed=20;  //max node speed in m/s
static const uint32_t tcpPacketSizeAuth = 1040;
uint32_t authPort = 88;
static const uint32_t k=3;//the degree of distribution parameter, representing the no. of nodes required for certificate verification

void setupmobility(double, double,double,NodeContainer,NodeContainer,uint32_t,int64_t,uint32_t,uint32_t); 
void GnbSetAttribute(uint32_t,NetDeviceContainer);
void updateConfigs(NetDeviceContainer,NetDeviceContainer);
void antennaSetup();
void sliceAttributeSetup();

//void WriteUntilBufferFull (Ptr<Socket>, uint32_t);
void CwndTracer (uint32_t , uint32_t );

class authProcess
{
public:
   authProcess(uint32_t,uint32_t,double,uint32_t);
   
   uint32_t currentTxBytes;

private:
   Ptr<Socket> sourceSocket;
   Ptr<Socket> destSocket;
   Ptr<Socket> HAKFsocket;
   Ptr<Socket>* intermediateSocket; 
   uint32_t source;
   uint32_t destination;
   double startTime;
   double endTime;
   uint8_t DATA[tcpPacketSizeAuth];
   uint32_t stage;/*stage=0: not started, 
                   stage=1:Auth Requested, 
                   stage=2: Auth req recieved and Ver Requested, 
                   stage=3: Ver req received and res sent, 
                   stage=4: ver res recieved and auth res sent, 
                   stage=5: Auth res recieved and Ver Requested, 
                   stage=6: Ver req received and res sent, 
                   stage=7: ver res received and authentication process terminated */
   bool authSuccess;
   uint32_t srcSideVerifiers[k];//The nodes that help the source node in certificate verification
   uint32_t destSideVerifiers[k];//The nodes that help the destination node in certificate verification
   bool srcSideVerRec[k];//Source-side boolean vector indicating the receive of the verification response from the corresponding verifier
   bool destSideVerRec[k];//Destination-side boolean vector indicating the receive of the verification response from the corresponding verifier
   bool srcSideVerResSent[k];//Source-side boolean vector indicating whether the verification req sent to the corresponding verifier or not
   bool destSideVerResSent[k];//Destination-side boolean vector indicating whether the verification req sent to the corresponding verifier or not
   bool srcSideVerResRecvd[k];//Source-side boolean vector indicating whether the verification res recieved from the corresponding verifier or not
   bool destSideVerResRecvd[k];//Destination-side boolean vector indicating whether the verification res recieved from the corresponding verifier or not
   uint32_t ueNum;//we need this variable inside the class to keep the cmd still able to get the enumber of UEs from the commandline
   
   void initAuthPacket();
   void authenticate();
   void acceptDest(Ptr<Socket>,const ns3::Address&);
   void receiveDest (Ptr<Socket>);   
   void verReq();
   void acceptVerReq(Ptr<Socket>,const ns3::Address&);
   void verRes(Ptr<Socket>);
   void authRes();
   void acceptSource(Ptr<Socket>,const ns3::Address&);
   void receiveSource (Ptr<Socket>);
   void selectVerifiers();
   bool acceptedAs(uint32_t,uint32_t,bool);
   bool allVerResSent();
   uint32_t verifierPos(uint32_t);//returns the position of the verifier in the verifiers vector
   uint32_t nodeId(Address);//returns the node id from its MAC address, node IDs start from 1 to ueNodes
   uint32_t verResps(bool*);//return number of received ver responses
};

authProcess::authProcess(uint32_t src, uint32_t dest,double authTime,uint32_t noOfUEs)
  : source(src),
    destination(dest),
    authSuccess(false),
    startTime(authTime),
    endTime(0),
    stage(0),
    currentTxBytes(0),
    ueNum(noOfUEs)
    
{
  intermediateSocket=new Ptr<Socket>[ueNum];
  for(int i=0;i<k;i++){
    srcSideVerRec[i]=false;
    destSideVerRec[i]=false;
    srcSideVerResSent[i]=false;
    destSideVerResSent[i]=false;
    srcSideVerResRecvd[i]=false;
    destSideVerResRecvd[i]=false;
  }
  initAuthPacket();
  selectVerifiers();
  Simulator::Schedule (Seconds (startTime), &authProcess::authenticate,this);
}

int
main(int argc, char* argv[])
{
    uint32_t gNbNum = 1;
    uint32_t ueNum = 4;
    
    double X=200.0;
    double Y=200.0;
    double Z=0.0;
    int64_t streamIndex = 0; // used to get consistent mobility across scenarios
    uint32_t mobilityModel=1;//1-RWP, 2-GaussMarkov   

    uint32_t udpPacketSizeVideo = 100;
    uint32_t udpPacketSizeVoice = 1252;
    uint32_t udpPacketSizeGaming = 500;
    uint32_t lambdaVideo = 50;
    uint32_t lambdaVoice = 100;
    uint32_t lambdaGaming = 250;

    uint32_t simTimeMs = 1000;
    uint32_t udpAppStartTimeMs = 10;

    double centralFrequencyBand1 = 2e9;//was 28e9
    double bandwidthBand1 = 100e6;
    double centralFrequencyBand2 = 2.2e9;//was 28.2e9
    double bandwidthBand2 = 100e6;
    double totalTxPower = 4;
    std::string simTag = "default";
    std::string outputDir = "./";
    bool enableVideo = true;
    bool enableVoice = true;
    bool enableGaming = true;

    CommandLine cmd(__FILE__);

    cmd.AddValue("packetSizeVideo",
                 "packet size in bytes to be used by video traffic",
                 udpPacketSizeVideo);
    cmd.AddValue("packetSizeVoice",
                 "packet size in bytes to be used by voice traffic",
                 udpPacketSizeVoice);
    cmd.AddValue("packetSizeGaming",
                 "packet size in bytes to be used by gaming traffic",
                 udpPacketSizeGaming);
    cmd.AddValue("lambdaVideo",
                 "Number of UDP packets in one second for video traffic",
                 lambdaVideo);
    cmd.AddValue("lambdaVoice",
                 "Number of UDP packets in one second for voice traffic",
                 lambdaVoice);
    cmd.AddValue("lambdaGaming",
                 "Number of UDP packets in one second for gaming traffic",
                 lambdaGaming);
    cmd.AddValue("enableVideo", "If true, enables video traffic transmission (DL)", enableVideo);
    cmd.AddValue("enableVoice", "If true, enables voice traffic transmission (DL)", enableVoice);
    cmd.AddValue("enableGaming", "If true, enables gaming traffic transmission (UL)", enableGaming);
    cmd.AddValue("simTimeMs", "Simulation time", simTimeMs);
    cmd.AddValue("centralFrequencyBand1",
                 "The system frequency to be used in band 1",
                 centralFrequencyBand1);
    cmd.AddValue("bandwidthBand1", "The system bandwidth to be used in band 1", bandwidthBand1);
    cmd.AddValue("centralFrequencyBand2",
                 "The system frequency to be used in band 2",
                 centralFrequencyBand2);
    cmd.AddValue("bandwidthBand2", "The system bandwidth to be used in band 2", bandwidthBand2);
    cmd.AddValue("totalTxPower",
                 "total tx power that will be proportionally assigned to"
                 " bands, CCs and bandwidth parts depending on each BWP bandwidth ",
                 totalTxPower);
    cmd.AddValue("simTag",
                 "tag to be appended to output filenames to distinguish simulation campaigns",
                 simTag);
    cmd.AddValue("outputDir", "directory where to store simulation results", outputDir);
    cmd.AddValue("X","Area width to echo",X);
    cmd.AddValue("Y","Area Length to echo",Y);
    cmd.AddValue("Z","Area height to echo",Z);
    cmd.AddValue("streamIndex", "Stream Index to echo", streamIndex);
    cmd.AddValue("mobilityModel", "Mobility model to echo (1-RWP, 2-GaussMarkov): ", mobilityModel);
    cmd.AddValue("nodeSpeed","Max node speed to echo",nodeSpeed);
    cmd.AddValue("ueNum","Number of UEs to echo",ueNum);

    cmd.Parse(argc, argv);

    NS_ABORT_IF(centralFrequencyBand1 > 100e9);
    NS_ABORT_IF(centralFrequencyBand2 > 100e9);

    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999999));
    gnbNodes.Create (gNbNum);
    ueNodes.Create (ueNum);
    

//##################### Helper Setup #####################
    //std::cout<<"Setting up the required Helpers..."<<std::endl;
    /*
     * TODO: Add a print, or a plot, that shows the scenario.
     */
    Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    nrHelper = CreateObject<NrHelper>();

    // Put the pointers inside nrHelper
    nrHelper->SetBeamformingHelper(idealBeamformingHelper);
    nrHelper->SetEpcHelper(epcHelper);
    
    // Core latency
    epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));
    
    // Beamforming method
    idealBeamformingHelper->SetAttribute("BeamformingMethod",
                                         TypeIdValue(DirectPathBeamforming::GetTypeId()));
//##################### Helper Setup #####################
    pgw = epcHelper->GetPgwNode();
    remoteHostContainer.Create(1);
    remoteHost = remoteHostContainer.Get(0);
//##################### Mobility Setup #####################
    //std::cout<<"Setting up the mobility..."<<std::endl;    
    setupmobility(X,Y,Z,ueNodes,gnbNodes,mobilityModel,streamIndex,gNbNum,ueNum);
//##################### Mobility Setup #####################

//##################### Bandwidth Setup #####################
    BandwidthPartInfoPtrVector allBwps;
    CcBwpCreator ccBwpCreator;
    const uint8_t numCcPerBand = 1; // in this example, both bands have a single CC
    CcBwpCreator::SimpleOperationBandConf bandConfTdd(centralFrequencyBand1,
                                                      bandwidthBand1,
                                                      numCcPerBand,
                                                      BandwidthPartInfo::UMi_StreetCanyon);
    CcBwpCreator::SimpleOperationBandConf bandConfFdd(centralFrequencyBand2,
                                                      bandwidthBand2,
                                                      numCcPerBand,
                                                      BandwidthPartInfo::UMi_StreetCanyon);
    bandConfFdd.m_numBwp = 2; // Here, bandFdd will have 2 BWPs
    // By using the configuration created, it is time to make the operation bands
    OperationBandInfo bandTdd = ccBwpCreator.CreateOperationBandContiguousCc(bandConfTdd);
    OperationBandInfo bandFdd = ccBwpCreator.CreateOperationBandContiguousCc(bandConfFdd);
    /*
     * The configured spectrum division is:
     * |------------BandTdd--------------|--------------BandFdd---------------|
     * |------------CC0------------------|--------------CC1-------------------|
     * |------------BWP0-----------------|------BWP1-------|-------BWP2-------|
     *
     * We will configure BWP0 as TDD, BWP1 as FDD-DL, BWP2 as FDD-UL.
     */     
//##################### Bandwidth Setup #####################     
    //std::cout<<"Setting up the bandwidth..."<<std::endl; 
    /*
     * Attributes of ThreeGppChannelModel still cannot be set in our way.
     * TODO: Coordinate with Tommaso
     */
    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(0)));
    nrHelper->SetChannelConditionModelAttribute("UpdatePeriod", TimeValue(MilliSeconds(0)));
    nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));

    nrHelper->InitializeOperationBand(&bandTdd);
    nrHelper->InitializeOperationBand(&bandFdd);
    allBwps = CcBwpCreator::GetAllBwps({bandTdd, bandFdd});




//##################### Antenna Setup #####################
    //std::cout<<"Setting up the Antennas..."<<std::endl;  
    antennaSetup();    
//##################### Antenna Setup #####################

//##################### Slice Attribute Setup #####################
    //std::cout<<"Setting up the slices' attributes..."<<std::endl;
    sliceAttributeSetup();
//##################### Slice Attribute Setup #####################
    
//Applying the setup slice attributes into the ueNodes and gNodeBs
    NetDeviceContainer enbNetDev =
        nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    NetDeviceContainer ueNetDev =
        nrHelper->InstallUeDevice(ueNodes, allBwps);
    
    randomStream += nrHelper->AssignStreams(enbNetDev, randomStream);
    randomStream += nrHelper->AssignStreams(ueNetDev, randomStream);
        
    // Set the UE routing:

    for (uint32_t i = 0; i < ueNetDev.GetN(); i++)
    {
        nrHelper->GetBwpManagerUe(ueNetDev.Get(i))->SetOutputLink(1, 2);
    }
   
    NS_ASSERT(enbNetDev.GetN() >= 1);
        
//##################### gNodeB Setup #####################
    //std::cout<<"Setting up the gNodeBs..."<<std::endl;    
    GnbSetAttribute(gNbNum,enbNetDev);
//##################### gNodeB Setup #####################


//##################### Updating Configs #####################  
    // When all the configuration is done, explicitly call UpdateConfig ()
    //std::cout<<"Updating the configs..."<<std::endl;
    updateConfigs(ueNetDev,enbNetDev);
//##################### Updating Configs #####################  

    // From here, it is standard NS3. In the future, we will create helpers
    // for this part as well.

//##################### IP Setup #####################  
    //std::cout<<"Setiing up the IPs..."<<std::endl;
    // create the internet and install the IP stack on the ueNodes
    // get SGW/PGW and create a single RemoteHost

    NetDeviceContainer internetDevices;
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);

    // connect a remoteHost to pgw. Setup routing too
    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.000)));
    internetDevices = p2ph.Install(pgw, remoteHost);
    Ipv4AddressHelper ipv4h;
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    internetIpIfaces = ipv4h.Assign(internetDevices);
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
        ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);
    internet.Install(ueNodes);
    
    
    ueIpIface = epcHelper->AssignUeIpv4Address(NetDeviceContainer(ueNetDev));    
//##################### IP Setup ##################### 

    // Set the default gateway for the ueNodes
    for (uint32_t j = 0; j < ueNodes.GetN(); ++j)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting = ipv4RoutingHelper.GetStaticRouting(
            ueNodes.Get(j)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }
    
    // Fix the attachment of the ueNodes: UE_i attached to GNB_i
    for (uint32_t i = 0; i < ueNetDev.GetN(); ++i)
    {
        auto enbDev = DynamicCast<NrGnbNetDevice>(enbNetDev.Get(0));
        auto ueDev = DynamicCast<NrUeNetDevice>(ueNetDev.Get(i));
        NS_ASSERT(enbDev != nullptr);
        NS_ASSERT(ueDev != nullptr);
        nrHelper->AttachToEnb(ueDev, enbDev);
    }
    
    /*
     * Traffic part. Install two kind of traffic: low-latency and voice, each
     * identified by a particular source port.
     */
    uint32_t dlPortVideo = 1234;
    uint32_t dlPortVoice = 1235;
    uint32_t ulPortGaming = 1236;

    ApplicationContainer serverApps;

    // The sink will always listen to the specified ports
    UdpServerHelper dlPacketSinkVideo(dlPortVideo);
    UdpServerHelper dlPacketSinkVoice(dlPortVoice);
    UdpServerHelper ulPacketSinkVoice(ulPortGaming);

    // The server, that is the application which is listening, is installed in the UE
    // for the DL traffic, and in the remote host for the UL traffic
    serverApps.Add(dlPacketSinkVideo.Install(ueNodes));
    serverApps.Add(dlPacketSinkVoice.Install(ueNodes));
    serverApps.Add(ulPacketSinkVoice.Install(remoteHost));

    /*
     * Configure attributes for the different generators, using user-provided
     * parameters for generating a CBR traffic
     *
     * Low-Latency configuration and object creation:
     */
    UdpClientHelper dlClientVideo;
    dlClientVideo.SetAttribute("RemotePort", UintegerValue(dlPortVideo));
    dlClientVideo.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
    dlClientVideo.SetAttribute("PacketSize", UintegerValue(udpPacketSizeVideo));
    dlClientVideo.SetAttribute("Interval", TimeValue(Seconds(1.0 / lambdaVideo)));

    // The bearer that will carry low latency traffic
    EpsBearer videoBearer(EpsBearer::GBR_CONV_VIDEO);

    // The filter for the low-latency traffic
    Ptr<EpcTft> videoTft = Create<EpcTft>();
    EpcTft::PacketFilter dlpfVideo;
    dlpfVideo.localPortStart = dlPortVideo;
    dlpfVideo.localPortEnd = dlPortVideo;
    videoTft->Add(dlpfVideo);

    // Voice configuration and object creation:
    UdpClientHelper dlClientVoice;
    dlClientVoice.SetAttribute("RemotePort", UintegerValue(dlPortVoice));
    dlClientVoice.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
    dlClientVoice.SetAttribute("PacketSize", UintegerValue(udpPacketSizeVoice));
    dlClientVoice.SetAttribute("Interval", TimeValue(Seconds(1.0 / lambdaVoice)));

    // The bearer that will carry voice traffic
    EpsBearer voiceBearer(EpsBearer::GBR_CONV_VOICE);

    // The filter for the voice traffic
    Ptr<EpcTft> voiceTft = Create<EpcTft>();
    EpcTft::PacketFilter dlpfVoice;
    dlpfVoice.localPortStart = dlPortVoice;
    dlpfVoice.localPortEnd = dlPortVoice;
    voiceTft->Add(dlpfVoice);

    // Gaming configuration and object creation:
    UdpClientHelper ulClientGaming;
    ulClientGaming.SetAttribute("RemotePort", UintegerValue(ulPortGaming));
    ulClientGaming.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
    ulClientGaming.SetAttribute("PacketSize", UintegerValue(udpPacketSizeGaming));
    ulClientGaming.SetAttribute("Interval", TimeValue(Seconds(1.0 / lambdaGaming)));

    // The bearer that will carry gaming traffic
    EpsBearer gamingBearer(EpsBearer::GBR_GAMING);

    // The filter for the gaming traffic
    Ptr<EpcTft> gamingTft = Create<EpcTft>();
    EpcTft::PacketFilter ulpfGaming;
    ulpfGaming.remotePortStart = ulPortGaming;
    ulpfGaming.remotePortEnd = ulPortGaming;
    ulpfGaming.direction = EpcTft::UPLINK;
    gamingTft->Add(ulpfGaming);

    /*
     * Let's install the applications!
     */
    ApplicationContainer clientApps;

    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
        Ptr<Node> ue = ueNodes.Get(i);
        Ptr<NetDevice> ueDevice = ueNetDev.Get(i);
        Address ueAddress = ueIpIface.GetAddress(i);
        //cout<<i<<": "<<ueAddress<<endl;
        // The client, who is transmitting, is installed in the remote host,
        // with destination address set to the address of the UE
        if (enableVoice)
        {
            dlClientVoice.SetAttribute("RemoteAddress", AddressValue(ueAddress));
            clientApps.Add(dlClientVoice.Install(remoteHost));

            nrHelper->ActivateDedicatedEpsBearer(ueDevice, voiceBearer, voiceTft);
        }

        if (enableVideo)
        {
            dlClientVideo.SetAttribute("RemoteAddress", AddressValue(ueAddress));
            clientApps.Add(dlClientVideo.Install(remoteHost));

            nrHelper->ActivateDedicatedEpsBearer(ueDevice, videoBearer, videoTft);
        }

        // For the uplink, the installation happens in the UE, and the remote address
        // is the one of the remote host

        if (enableGaming)
        {
            ulClientGaming.SetAttribute("RemoteAddress",
                                        AddressValue(internetIpIfaces.GetAddress(1)));
            clientApps.Add(ulClientGaming.Install(ue));

            nrHelper->ActivateDedicatedEpsBearer(ueDevice, gamingBearer, gamingTft);
        }
    }

    // start UDP server and client apps
    serverApps.Start(MilliSeconds(udpAppStartTimeMs));
    clientApps.Start(MilliSeconds(udpAppStartTimeMs));
    serverApps.Stop(MilliSeconds(simTimeMs));
    clientApps.Stop(MilliSeconds(simTimeMs));

    // enable the traces provided by the nr module
    //nrHelper->EnableTraces();

    FlowMonitorHelper flowmonHelper;
    NodeContainer endpointNodes;
    endpointNodes.Add(remoteHost);
    endpointNodes.Add(ueNodes);

    Ptr<ns3::FlowMonitor> monitor = flowmonHelper.Install(endpointNodes);
    monitor->SetAttribute("DelayBinWidth", DoubleValue(0.001));
    monitor->SetAttribute("JitterBinWidth", DoubleValue(0.001));
    monitor->SetAttribute("PacketSizeBinWidth", DoubleValue(20));
    
    AnimationInterface anim ("SCC5G.xml");
    anim.SetMaxPktsPerTraceFile (200000000);
    
    double authTime=.1;//sec
    authProcess authenticationInstance(0, 1,authTime,ueNum);//the node numbering tarts from 0 to ueNum-1
    
    Simulator::Stop(MilliSeconds(simTimeMs));
    Simulator::Run();

    // Print per-flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    double averageFlowThroughput = 0.0;
    double averageFlowDelay = 0.0;

    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin();
         i != stats.end();
         ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        std::stringstream protoStream;
        protoStream << (uint32_t)t.protocol;
        if (t.protocol == 6)
        {
            protoStream.str("TCP");
        }
        if (t.protocol == 17)
        {
            protoStream.str("UDP");
        }
        if (i->second.rxPackets > 0)
        {
            double rxDuration = (simTimeMs - udpAppStartTimeMs) / 1000.0;

            averageFlowThroughput += i->second.rxBytes * 8.0 / rxDuration / 1000 / 1000;
            averageFlowDelay += 1000 * i->second.delaySum.GetSeconds() / i->second.rxPackets;
        }
    }
    cout<< "Mean flow throughput: " << averageFlowThroughput / stats.size() << endl;
    cout<< "Mean flow delay: " << averageFlowDelay / stats.size() << endl;
    cout<< "Authentication Traffic: " << authenticationInstance.currentTxBytes <<" Bytes"<< endl;

    Simulator::Destroy();
    return 0;
}
//############################# End of the Main() ############################

void setupmobility(double X, double Y, double Z, NodeContainer ueNodes,NodeContainer gnbNodes,uint32_t mobilityModel,int64_t streamIndex,uint32_t gNbNum,uint32_t ueNum)
{
//setup gNodeBs
    double distance = X/(gNbNum+1); 
    Ptr<ListPositionAllocator> gnbPositionAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < gNbNum; i++)
    {
        Vector gnbPosition(distance * (i + 1), Y/2, 0);
        gnbPositionAlloc->Add(gnbPosition);
    }
    mobilityGnbs.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityGnbs.SetPositionAllocator(gnbPositionAlloc);
    mobilityGnbs.Install(gnbNodes);
    
    mobilityOtherNodes.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityOtherNodes.SetPositionAllocator(gnbPositionAlloc);
    mobilityOtherNodes.Install(pgw);
    mobilityOtherNodes.Install(remoteHost);
    //mobilityOtherNodes.Install(internetDevices);
    
//Setup ueNodes

  ObjectFactory pos;
  std::stringstream sX;
  std::stringstream sY;
  std::stringstream sZ;
  sX<<"ns3::UniformRandomVariable[Min=0.0|Max="<<X<<"]";
  sY<<"ns3::UniformRandomVariable[Min=0.0|Max="<<Y<<"]";
  sZ<<"ns3::UniformRandomVariable[Min=0.0|Max="<<Z<<"]";
  
  pos.SetTypeId ("ns3::RandomBoxPositionAllocator");
  pos.Set ("X", StringValue (sX.str()));
  pos.Set ("Y", StringValue (sY.str()));
  pos.Set ("Z", StringValue (sZ.str()));

  Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  streamIndex += taPositionAlloc->AssignStreams (streamIndex);

  int nodePause = 0; //in s
  double direction=6.283185307; // in radian
  double pitch=0.05; // in radian

  std::stringstream ssSpeed;
  ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
  std::stringstream ssPause;
  ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
  std::stringstream ssDirection;
  ssDirection << "ns3::UniformRandomVariable[Min=0|Max=" << direction << "]";
  std::stringstream ssPitch;
  ssPitch << "ns3::UniformRandomVariable[Min="<< pitch <<"|Max=" << pitch << "]";
  std::stringstream ssNormVelocity;
  ssNormVelocity <<"ns3::NormalRandomVariable[Mean=0.0|Variance=0.0|Bound=0.0]";
  std::stringstream ssNormDirection;
  ssNormDirection <<"ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]";
  std::stringstream ssNormPitch;
  ssNormPitch <<"ns3::NormalRandomVariable[Mean=0.0|Variance=0.02|Bound=0.04]";

  switch (mobilityModel)
    {
    case 1:
      mobilityUEs.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                                  "Speed", StringValue (ssSpeed.str ()),
                                  "Pause", StringValue (ssPause.str ()),
                                  "PositionAllocator", PointerValue (taPositionAlloc));
      break;
    case 2:
      mobilityUEs.SetMobilityModel ("ns3::GaussMarkovMobilityModel",
                     "Bounds", BoxValue (Box (0, X, 0, Y, 0, Z)),
                     "TimeStep", TimeValue (Seconds (0.5)),
                     "Alpha", DoubleValue (0.85),
                     "MeanVelocity", StringValue (ssSpeed.str()),
                     "MeanDirection", StringValue (ssDirection.str()),
                     "MeanPitch", StringValue (ssPitch.str()),
                     "NormalVelocity", StringValue (ssNormVelocity.str()),
                     "NormalDirection", StringValue (ssNormDirection.str()),
                     "NormalPitch", StringValue (ssNormPitch.str()));
      break;
/*    case 3:
      mobilityUEs.SetMobilityModel ("ns3::SteadyStateRandomWaypointMobilityModel",
                                  //"Speed", StringValue (ssSpeed.str ()),
                                  //"Pause", StringValue (ssPause.str ()),
                                  "PositionAllocator", PointerValue (taPositionAllocSSRWP));
      
      break;
    case 4:
      mobilityUEs.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                              "Mode", StringValue ("Time"),
                              "Time", StringValue ("2s"),
                              "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"),
                              "Bounds", BoxValue (Box (0, X, 0, Y, 0, Z)));
*/
    default:
      NS_FATAL_ERROR ("No such model:" << mobilityModel);
    }
  


/*If you want to fix the node positions

mobilityUEs.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
        Vector node1_Position(0.1, 0.1, 0.0);
	Vector node2_Position(50.0, 0.1,0.0);
	Vector node3_Position(100.0, 0.1, 0.0);	

	ListPositionAllocator myListPositionAllocator;
	myListPositionAllocator.Add(node1_Position);
	myListPositionAllocator.Add(node2_Position);
	myListPositionAllocator.Add(node3_Position);
	
	mobilityUEs.SetPositionAllocator(&myListPositionAllocator);
*/

  mobilityUEs.SetPositionAllocator (taPositionAlloc);
  mobilityUEs.Install (ueNodes);
  streamIndex += mobilityUEs.AssignStreams (ueNodes, streamIndex);
  NS_UNUSED (streamIndex); // From this point, streamIndex is unused
}


void GnbSetAttribute(uint32_t gNbNum,NetDeviceContainer enbNetDev)
{

  for(int i=0; i<gNbNum;i++)//for each gNodeB
     {
        // BWP0, the TDD one
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 0)->SetAttribute("Numerology", UintegerValue(i));
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 0)
                ->SetAttribute("Pattern", StringValue("F|F|F|F|F|F|F|F|F|F|"));
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 0)->SetAttribute("TxPower", DoubleValue(4.0));

        // BWP1, FDD-DL
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 1)->SetAttribute("Numerology", UintegerValue(i));
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 1)
                ->SetAttribute("Pattern", StringValue("DL|DL|DL|DL|DL|DL|DL|DL|DL|DL|"));
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 1)->SetAttribute("TxPower", DoubleValue(4.0));

        // BWP2, FDD-UL
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 2)->SetAttribute("Numerology", UintegerValue(i));
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 2)
                ->SetAttribute("Pattern", StringValue("UL|UL|UL|UL|UL|UL|UL|UL|UL|UL|"));
        nrHelper->GetGnbPhy(enbNetDev.Get(i), 2)->SetAttribute("TxPower", DoubleValue(0.0));

        // Link the two FDD BWP:
        nrHelper->GetBwpManagerGnb(enbNetDev.Get(i))->SetOutputLink(2, 1);
     }   
}
    
void updateConfigs(NetDeviceContainer ueNetDev,NetDeviceContainer enbNetDev)
{
    for (auto it = enbNetDev.Begin(); it != enbNetDev.End(); ++it)
    {
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    }
    for (auto it = ueNetDev.Begin(); it != ueNetDev.End(); ++it)
    {
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
    }
    
}

void antennaSetup()
{
    // Antennas for all the UEs
    nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(2));
    nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(4));
    nrHelper->SetUeAntennaAttribute("AntennaElement",
                                    PointerValue(CreateObject<IsotropicAntennaModel>()));

    // Antennas for all the gNbs
    nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    nrHelper->SetGnbAntennaAttribute("AntennaElement",
                                     PointerValue(CreateObject<IsotropicAntennaModel>()));

    nrHelper->SetGnbPhyAttribute("TxPower", DoubleValue(4.0));
}

void sliceAttributeSetup()
{
    uint32_t bwpIdForVoice = 0;
    uint32_t bwpIdForVideo = 1;
    uint32_t bwpIdForGaming = 2;

    nrHelper->SetGnbBwpManagerAlgorithmAttribute("GBR_CONV_VOICE", UintegerValue(bwpIdForVoice));
    nrHelper->SetGnbBwpManagerAlgorithmAttribute("GBR_CONV_VIDEO", UintegerValue(bwpIdForVideo));
    nrHelper->SetGnbBwpManagerAlgorithmAttribute("GBR_GAMING", UintegerValue(bwpIdForGaming));

    nrHelper->SetUeBwpManagerAlgorithmAttribute("GBR_CONV_VOICE", UintegerValue(bwpIdForVoice));
    nrHelper->SetUeBwpManagerAlgorithmAttribute("GBR_CONV_VIDEO", UintegerValue(bwpIdForVideo));
    nrHelper->SetUeBwpManagerAlgorithmAttribute("GBR_GAMING", UintegerValue(bwpIdForGaming));
}

void
authProcess::authenticate()
{   
  //Create and bind a destination socket... 
  destSocket = Socket::CreateSocket (ueNodes.Get (this->destination),    TcpSocketFactory::GetTypeId ()); 
  TypeId tid = TypeId::LookupByName ("ns3::TcpNewReno");
  Config::Set ("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue (tid));
  InetSocketAddress local= InetSocketAddress (Ipv4Address::GetAny (), authPort);
  destSocket->Bind(local);
  destSocket->Listen();
  destSocket->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>,const Address &> (),MakeCallback(&authProcess::acceptDest,this));  
  // Create and bind a source socket...
  sourceSocket= Socket::CreateSocket (ueNodes.Get (this->source),  TcpSocketFactory::GetTypeId ());
  sourceSocket->Bind ();
  sourceSocket->Connect (InetSocketAddress (ueIpIface.GetAddress (this->destination), authPort)); 
  bool flag=false;//Flag representing the channel unavailability
  while (!flag)
  {
     if(sourceSocket->GetTxAvailable ()>= tcpPacketSizeAuth)
        flag=true;
     int amountSent = sourceSocket->Send (&DATA[tcpPacketSizeAuth], tcpPacketSizeAuth, 0);
     this->stage=1; //Authentication requested 
     //cout<<"Stage 1"<<endl;    
       if(amountSent > 0)
         this->currentTxBytes+=amountSent;
       else if(amountSent < 0)
  {
     return;  
  }
  }    

  // Trace changes to the congestion window
  Config::ConnectWithoutContext ("/NodeList/*/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer)); 
}

void 
authProcess::acceptDest(Ptr<Socket> socket,const ns3::Address& from)
{ 
  socket->SetRecvCallback (MakeCallback (&authProcess::receiveDest,this));
}

void 
authProcess::acceptSource(Ptr<Socket> socket,const ns3::Address& from)
{ 
  socket->SetRecvCallback (MakeCallback (&authProcess::receiveSource,this));
}

void CwndTracer (uint32_t oldval, uint32_t newval)
{
  NS_LOG_INFO ("Moving cwnd from " << oldval << " to " << newval);
}

void 
authProcess::receiveDest (Ptr<Socket> socket)
 { 
   Address fromAddress;//MAC address
   Ptr<Packet> packet = socket->RecvFrom (INT_MAX,false,fromAddress);
   uint32_t sender=nodeId(fromAddress)-1;
   uint32_t pos=verifierPos(sender);
   if(this->stage==1){//Authentication Request     
     verReq();
   }
   else if(verResps(destSideVerResRecvd)<k && destSideVerResSent[pos] && !destSideVerResRecvd[pos] ){//Verification response
     destSideVerResRecvd[pos]=true;
     //cout<<"receiveDest (Verification response), stage: "<<this->stage<<" verResps(destSideVerResRecvd): "<<verResps(destSideVerResRecvd)<<endl;
     if(verResps(destSideVerResRecvd)==k)
        authRes();
     }    
 }

void
authProcess::initAuthPacket()
{
  // initialize the authentication packet buffer.
  for(uint32_t i = 0; i < tcpPacketSizeAuth; ++i)
    {
      char m = toascii (97 + i % 26);
      DATA[i] = m;
    }
}

void 
authProcess::verReq(){
 int amountSent=0;  
 //Create and bind a socket for k verifiers...
 //######################################################## 
 for(int i=0;i<k;i++){
    if(stage==1){//Authentication requested
       //Create and bind a socket for the verifiers...
       intermediateSocket[destSideVerifiers[i]] = Socket::CreateSocket (ueNodes.Get (destSideVerifiers[i]),    TcpSocketFactory::GetTypeId ());  
       TypeId tid = TypeId::LookupByName ("ns3::TcpNewReno");
       Config::Set ("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue (tid));
       InetSocketAddress local= InetSocketAddress (Ipv4Address::GetAny (), authPort);
       intermediateSocket[destSideVerifiers[i]]->Bind(local);
       intermediateSocket[destSideVerifiers[i]]->Listen();
       intermediateSocket[destSideVerifiers[i]]->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>,const Address &> (),MakeCallback(&authProcess::acceptVerReq,this));
     
       //########################################################  
       // Create and bind a source socket...
       destSocket= Socket::CreateSocket (ueNodes.Get (this->destination),  TcpSocketFactory::GetTypeId ());
       destSocket->Bind ();
       destSocket->Connect (InetSocketAddress (ueIpIface.GetAddress(destSideVerifiers[i]), authPort)); 
       bool flag=false;//Flag representing the channel unavailability
       while (!flag)
       {
          if(destSocket->GetTxAvailable ()>= tcpPacketSizeAuth)
             flag=true;
          amountSent=0;
          amountSent = destSocket->Send (&DATA[tcpPacketSizeAuth], tcpPacketSizeAuth, 0);     
       }
       if(i==k-1){//after the last request send
          this->stage=2;//stage=2 Auth req received and verification requested
          //cout<<"Stage 2"<<endl;  
       }
    }
    
    if(stage==4){//authentication response has sent
       //Create and bind a socket for the verifiers...
       intermediateSocket[srcSideVerifiers[i]] = Socket::CreateSocket (ueNodes.Get (srcSideVerifiers[i]),    TcpSocketFactory::GetTypeId ());  
       TypeId tid = TypeId::LookupByName ("ns3::TcpNewReno");
       Config::Set ("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue (tid));
       InetSocketAddress local= InetSocketAddress (Ipv4Address::GetAny (), authPort);
       intermediateSocket[srcSideVerifiers[i]]->Bind(local);
       intermediateSocket[srcSideVerifiers[i]]->Listen();
       intermediateSocket[srcSideVerifiers[i]]->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>,const Address &> (),MakeCallback(&authProcess::acceptVerReq,this));
       //########################################################  
       // Create and bind a source socket...
       sourceSocket= Socket::CreateSocket (ueNodes.Get (this->source),  TcpSocketFactory::GetTypeId ());
       sourceSocket->Bind ();
       sourceSocket->Connect (InetSocketAddress (ueIpIface.GetAddress(srcSideVerifiers[i]), authPort)); 
       bool flag=false;//Flag representing the channel unavailability
       while (!flag)
       {
          if(sourceSocket->GetTxAvailable ()>= tcpPacketSizeAuth)
             flag=true;
          amountSent=0;
          amountSent = sourceSocket->Send (&DATA[tcpPacketSizeAuth], tcpPacketSizeAuth, 0);
       }
       if(i==k-1){//after the last request send
          this->stage=5;//stage=5 Auth res received and verification requested
          //cout<<"Stage 5"<<endl; 
       }          
         } 
         
    if(amountSent > 0)
         this->currentTxBytes+=amountSent;
    else if(amountSent < 0)
    {
       return;  
    }  
    // Trace changes to the congestion window
    Config::ConnectWithoutContext ("/NodeList/*/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer)); 
    
 }  
}

void 
authProcess::acceptVerReq(Ptr<Socket> socket,const ns3::Address& from)
{ 
  verRes(socket);
}

void 
authProcess::verRes(Ptr<Socket> socket){
  
  Ptr<Packet> packet = socket->Recv ();
  uint32_t sender=socket->GetNode()->GetId()-1;//node ID is starting from 1 to ueNum, but the nodes are called by their labels which are 0 to ueNum-1
  uint32_t pos=verifierPos(sender);
  if(this->stage<4){//Auth req received by destination and ver request is sent
    destSideVerRec[pos]=true;
    destSocket = Socket::CreateSocket (ueNodes.Get (this->destination),    TcpSocketFactory::GetTypeId ());  
  TypeId tid = TypeId::LookupByName ("ns3::TcpNewReno");
  Config::Set ("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue (tid));
  InetSocketAddress local= InetSocketAddress (Ipv4Address::GetAny (), authPort);
  destSocket->Bind(local);
  destSocket->Listen(); 
  // Create and bind a source socket...
  intermediateSocket[sender]= Socket::CreateSocket (ueNodes.Get (sender),  TcpSocketFactory::GetTypeId ());
  intermediateSocket[sender]->Bind ();
  intermediateSocket[sender]->Connect (InetSocketAddress (ueIpIface.GetAddress (this->destination), authPort)); 
    while (!destSideVerResSent[pos]){
       if(intermediateSocket[sender]->GetTxAvailable ()>= tcpPacketSizeAuth){
          destSideVerResSent[pos]=true;
          //cout<<"Node "<<sender<<" sent ver res, pos= "<<pos<<" "<<destSideVerResSent[pos]<<" "<<allVerResSent()<<endl;
          if(allVerResSent()){
             this->stage=3;//stage=3 verif. req received from dest and verif. res sent
             //cout<<"Stage 3"<<endl; 
             //cout<<"allVerResSent(), stage: "<<this->stage<<endl;
          }
          int amountSent = intermediateSocket[sender]->Send (&DATA[tcpPacketSizeAuth], tcpPacketSizeAuth, 0);
          if(amountSent > 0)
             this->currentTxBytes+=amountSent;
          else if(amountSent < 0){
             return;  
          }
       }         
  }
 }
//############################################################  
  else{//Auth res received by source node and verification request is sent
  srcSideVerRec[pos]=true;
  sourceSocket = Socket::CreateSocket (ueNodes.Get (this->source),    TcpSocketFactory::GetTypeId ());  
  TypeId tid = TypeId::LookupByName ("ns3::TcpNewReno");
  Config::Set ("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue (tid));
  InetSocketAddress local= InetSocketAddress (Ipv4Address::GetAny (), authPort);
  sourceSocket->Bind(local);
  sourceSocket->Listen();
  
  // Create and bind a source socket...
  intermediateSocket[sender]= Socket::CreateSocket (ueNodes.Get (sender),  TcpSocketFactory::GetTypeId ());
  intermediateSocket[sender]->Bind ();
  intermediateSocket[sender]->Connect (InetSocketAddress (ueIpIface.GetAddress (this->source), authPort)); 

    while (!srcSideVerResSent[pos])
    {
       if(intermediateSocket[sender]->GetTxAvailable ()>= tcpPacketSizeAuth)
         srcSideVerResSent[pos]=true;
       int amountSent = intermediateSocket[sender]->Send (&DATA[tcpPacketSizeAuth], tcpPacketSizeAuth, 0);
       if(amountSent > 0){          
          this->currentTxBytes+=amountSent;
       }         
       else if(amountSent < 0){
          return;  
       }
       if(allVerResSent() && this->stage!=6){
          this->stage=6;//stage=6 verif. req received from source and verif. res sent
          //cout<<"Stage 6"<<endl; 
          //cout<<"allVerResSent(), stage: "<<this->stage<<endl;
       }
  }
 }
  // Trace changes to the congestion window
  Config::ConnectWithoutContext ("/NodeList/*/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer)); 
}

void
authProcess::authRes()
{
  //Create and bind a destination socket... 
  sourceSocket = Socket::CreateSocket (ueNodes.Get (this->source),    TcpSocketFactory::GetTypeId ());  
  TypeId tid = TypeId::LookupByName ("ns3::TcpNewReno");
  Config::Set ("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue (tid));
  InetSocketAddress local= InetSocketAddress (Ipv4Address::GetAny (), authPort);
  sourceSocket->Bind(local);
  sourceSocket->Listen();
  sourceSocket->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>,const Address &> (),MakeCallback(&authProcess::acceptSource,this));
  // Create and bind a source socket...
  destSocket= Socket::CreateSocket (ueNodes.Get (this->destination),  TcpSocketFactory::GetTypeId ());
  destSocket->Bind ();
  destSocket->Connect (InetSocketAddress (ueIpIface.GetAddress (this->source), authPort)); 
  bool flag=false;//Flag representing the channel unavailability
  while (!flag)
  {
     if(destSocket->GetTxAvailable ()>= tcpPacketSizeAuth)
        flag=true;
     int amountSent = destSocket->Send (&DATA[tcpPacketSizeAuth], tcpPacketSizeAuth, 0);
     this->stage=4; //verification response has received by the destination and authentication response has sent to the source 
     //cout<<"Stage 4"<<endl; 
     this->destSocket->Close();
       if(amountSent > 0)
         this->currentTxBytes+=amountSent;
       else if(amountSent < 0)
  {
     return;  
  }
  }    

  // Trace changes to the congestion window
  Config::ConnectWithoutContext ("/NodeList/*/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer)); 
}

void
authProcess::receiveSource(Ptr<Socket> socket){
  Address fromAddress;//MAC address
  Ptr<Packet> packet = socket->RecvFrom (INT_MAX,false,fromAddress);
  uint32_t sender=nodeId(fromAddress)-1;
  uint32_t pos=verifierPos(sender);
  if(this->stage==4 )
     verReq();
  else if( verResps(srcSideVerResRecvd)<k && srcSideVerResSent[pos] && !srcSideVerResRecvd[pos]){//verifiation response sent to the source node
    srcSideVerResRecvd[pos]=true;
    intermediateSocket[sender]->Close();
    //cout<<"receiveSrc (Verification response), stage: "<<this->stage<<" verResps(srcSideVerResRecvd): "<<verResps(srcSideVerResRecvd)<<endl;
    if(verResps(srcSideVerResRecvd)==k){
       this->stage=7;//Authentication process terminated
       //cout<<"Stage 7"<<endl; 
       this->authSuccess=true;
       this->sourceSocket->Close();
       if(endTime==0)  
          this->endTime=Simulator::Now ().GetSeconds ();
       cout<<"Authentication time: "<<this->endTime-this->startTime<<" Sec"<<endl;
    }
 }
}
void
authProcess::selectVerifiers(){
  bool flag=false;
  uint32_t verifier;
  for(uint32_t i=0;i<k;i++){//Choosing srcSideVerifiers
     flag=false;
     while(!flag){
        verifier=rand()%ueNum;
        if(acceptedAs(verifier,i,false)){//false indicates that it is for srcSideVerifiers
           this->srcSideVerifiers[i]=verifier;
           flag=true;
        }           
     }     
  } 
  
  for(uint32_t i=0;i<k;i++){//Choosing destSideVerifiers
     flag=false;
     while(!flag){
        verifier=rand()%ueNum;
        if(acceptedAs(verifier,i,true)){//true indicates that it is for destSideVerifiers
           this->destSideVerifiers[i]=verifier;
           flag=true;
        }           
     }     
  }
}

bool
authProcess::acceptedAs(uint32_t verifier,uint32_t noOfChosenVerifiers,bool srcOrDest){
   if(verifier==this->source || verifier==this->destination)
      return false;
   else if(!srcOrDest){
      for(int i=0;i<noOfChosenVerifiers;i++){
         if(this->srcSideVerifiers[i]==verifier)
            return false;
            }
   }
   else if(srcOrDest){
      for(int i=0;i<noOfChosenVerifiers;i++){
         if(this->destSideVerifiers[i]==verifier)
            return false;
            }
   }
   return true;      
}

bool
authProcess::allVerResSent(){
   if(this->stage<=2){
      for(uint32_t i=0;i<k;i++){
         if(destSideVerResSent[i]==false)
            return false;
            }
   } 
   else{
      for(uint32_t i=0;i<k;i++){
         if(srcSideVerResSent[i]==false)
            return false;
            }
   }            
   return true;
}

uint32_t
authProcess::verifierPos(uint32_t verifier){
   if(this->stage<=4){
      for(int i=0;i<k;i++){
         if(destSideVerifiers[i]==verifier)
            return i;
         }
   }   
   else if(this->stage>4){
      for(int i=0;i<k;i++){
         if(srcSideVerifiers[i]==verifier)
            return i;
         }
   }   
}
uint32_t authProcess::nodeId(Address addrs){//returns node ID for provided MAC address, Node IDs starts from 1 to ueNode
   uint8_t* s;
   s=new uint8_t(1000);
   addrs.CopyTo(s);
   return (uint16_t)s[3]-1;
}

uint32_t
authProcess::verResps(bool* verResRecvd){
   uint32_t count=0;
   for(int i=0;i<k;i++){
      if(verResRecvd[i])
         count++;
         }
   return count;
}

package com.github.xuejike.rtp;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 嗅探
 * @author xuejike
 */
public class RtpSniffing {
    protected RtpAnalysis rtpAnalysis;
    protected PcapHandle handle;
    protected boolean status=false;

    public RtpSniffing(RtpAnalysis rtpAnalysis) {
        this.rtpAnalysis = rtpAnalysis;
    }

    public void start(String ip){
        close();
        status=true;
        PcapNetworkInterface nif = null;
        try {
            InetAddress addr = InetAddress.getByName(ip);

            nif = Pcaps.getDevByAddress(addr);
            int snaplen = 64 * 1024;
            // 超时50ms
            int timeout = 50;
            // 初始化抓包器
            PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(snaplen)
                    .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS).timeoutMillis(timeout)
                    .bufferSize(1 * 1024 * 1024);
            handle = phb.build();
            handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, timeout);
//
//        /** 设置TCP过滤规则 */
            String filter = "udp";
//
//        // 设置过滤器
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);


            new Thread(()->{
                do {
                    try {
                        if (handle != null){
                            Packet nextPacketEx = handle.getNextPacketEx();
                            if (nextPacketEx != null){
                                rtpAnalysis.read(nextPacketEx);
                            }
                        }

                    } catch (Exception e) {

                    }
                }while (status);
            }).start();

        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

    }

    public void close() {
        status =false;

    }
}

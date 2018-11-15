import com.github.xuejike.rtp.RtpAnalysis;
import com.github.xuejike.rtp.RtpSniffing;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import it.sauronsoftware.jave.AudioAttributes;
import it.sauronsoftware.jave.Encoder;
import it.sauronsoftware.jave.EncoderException;
import it.sauronsoftware.jave.EncodingAttributes;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.StaticUdpPortPacketFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;

/**
 * @author xuejike
 */
public class Main {

    protected static Packet nextPacket;
    protected static Packet payload;

    public static void   main0(String [] args) throws PcapNativeException, NotOpenException, InterruptedException, IOException, TimeoutException, IllegalRawDataException, UnirestException, EncoderException {

//
//        Encoder encoder = new Encoder();
//        AudioAttributes audio = new AudioAttributes();
//        audio.setCodec("libmp3lame");
//        audio.setBitRate(new Integer(128000));
//        audio.setChannels(new Integer(2));
//        audio.setSamplingRate(new Integer(8000));
//        EncodingAttributes attrs = new EncodingAttributes();
//        attrs.setFormat("mp3");
//        attrs.setAudioAttributes(audio);
//        encoder.encode(new File("E:\\project\\tel-rtp\\11_55_27_0c166b43.wav"),new File("test.mp3"),attrs);

    }



}

import com.github.xuejike.rtp.RtpAnalysis;
import com.github.xuejike.rtp.RtpSniffing;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * @author xuejike
 */
public class Main {

    protected static Packet nextPacket;
    protected static Packet payload;

    public static void   main(String [] args) throws PcapNativeException, NotOpenException, InterruptedException, IOException, TimeoutException {
        byte[] bytes = {0, 1, 2, 3};
        byte[] bytes1 = Arrays.copyOfRange(bytes, 1, 3);
        RtpSniffing rtpSniffing = new RtpSniffing(new RtpAnalysis());
        rtpSniffing.start("192.168.1.155");
        Thread.sleep(1000*60*60*24);


//        fileOutputStream.close();

    }



}

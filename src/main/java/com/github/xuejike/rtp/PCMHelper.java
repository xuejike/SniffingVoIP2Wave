package com.github.xuejike.rtp;


import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ws.schild.jave.*;

import java.io.*;

/**
 * @author xuejike
 */
public class PCMHelper {
    static Logger logger = LoggerFactory.getLogger(PCMHelper.class);
    private final static int HEADER_LENGTH = 50;

    private final static byte[] RIFF_array = { 'R', 'I', 'F', 'F' };
    private final static byte[] WAVE_array = { 'W', 'A', 'V', 'E' };
    private final static byte[] fmt_array = { 'f', 'm', 't', ' '};
    private final static byte[] fact_array = { 'f', 'a', 'c', 't'};
    private final static byte[] data_array = {'d', 'a', 't', 'a'};

    /**
     * Add wave header at front pcm data.
     *
     * @param data byte array of pcm data
     * @param channel pcm channel, e.g. 1 or 2
     * @param sampleRate pcm sample rate, e.g. 22050, 44100 etc.
     * @param bits pcm bits, e.g. 8 or 16
     * @return
     */
    public static byte[] PCM2Wave(byte[] data, int channel, int sampleRate, int bits) {
        int riffSize = data.length + HEADER_LENGTH;
        int chunk = channel * bits / 8;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            // Write RIFF header
            dos.write(RIFF_array);
            dos.write(intToByteArray(riffSize));
            dos.write(WAVE_array);

            // Write format header
            dos.write(fmt_array);
            dos.write(intToByteArray(18));
            dos.write(shortToByteArray(6));
            dos.write(shortToByteArray(channel));
            dos.write(intToByteArray(sampleRate));
            dos.write(intToByteArray(8000));
            dos.write(shortToByteArray(chunk));
            dos.write(intToByteArray(bits));
            dos.write(fact_array);
            dos.write(intToByteArray(4));
            dos.write(intToByteArray(480000));

            // Write data section
            dos.write(data_array);
            dos.write(intToByteArray(data.length));
            dos.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return baos.toByteArray();
    }
    public static void PCM2Wave(byte[] data, int channel, int sampleRate, int bits,String path) throws IOException {
        File file = new File(path);
        if (!file.exists()){
            boolean newFile = file.createNewFile();
            if (newFile){
                byte[] wave = PCM2Wave(data, channel, sampleRate, bits);
                FileOutputStream stream = new FileOutputStream(file);
                stream.write(wave);
                stream.close();
            }else{
                logger.error("文件创建失败");
            }
        }else{
            logger.error("文件已经存在");
        }
    }

    public static void wav2Mp3(byte[] data, String filePath){
        try {
            File pcm = File.createTempFile("pcm", ".wav");
            FileUtils.writeByteArrayToFile(pcm,data);
            Encoder encoder = new Encoder();
            AudioAttributes audio = new AudioAttributes();
            audio.setCodec("libmp3lame");
            audio.setBitRate(128000);
            audio.setChannels(2);
            audio.setSamplingRate(8000);
            EncodingAttributes attrs = new EncodingAttributes();
            attrs.setFormat("mp3");
            attrs.setAudioAttributes(audio);
            encoder.encode(new MultimediaObject(pcm),new File(filePath),attrs);


        } catch (Exception e) {
            try {
                FileUtils.writeByteArrayToFile(new File(filePath),data);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            if (e instanceof IOException){
                logger.error("pcm2Mp3:文件创建失败",e);
            }else if (e instanceof EncoderException){
                logger.error("pcm2Mp3:MP3编码错误",e);
            }else{
                logger.error("pcm2Mp3:文件输出异常",e);
            }
            try {
                if (new File(filePath).exists()){
                    logger.error("文件已存在,无法创建:{}",filePath);
                }else{
                    FileUtils.writeByteArrayToFile(new File(filePath),data);
                }

            } catch (IOException e1) {
                logger.error("pcm2Mp3:文件创建失败:{}",filePath,e);
            }

        }

    }
    /**
     * att. Little Endian
     *
     * @param value
     * @return
     */
    private static byte[] intToByteArray(int value) {
        return new byte[] { (byte) value, (byte) (value >>> 8),
                (byte) (value >>> 16), (byte) (value >>> 24)};
    }


    /**
     * att. Little Endian
     *
     * @param value
     * @return
     */
    private static byte[] shortToByteArray(int value) {
        return new byte[] { (byte) value, (byte) (value >>> 8) };
    }

    public static final String bytesToHexString(byte[] bArray) {
        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2) {
                sb.append(0);
            }
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }
}

package com.github.xuejike.rtp;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * 带定时清除的缓存
 * @author xueji
 */
public class KCache {
    private ConcurrentHashMap<String,KCacheItem> data;
    private ScheduledFuture<?> schedule;
    private Thread thread;


    public KCache(int initialCapacity) {
        data = new ConcurrentHashMap<>(initialCapacity);
        startSchedule();
    }

    public KCache() {
        data = new ConcurrentHashMap<>();
        startSchedule();
    }
    public void startSchedule(){
        ScheduledExecutorService pool = Executors
                .newScheduledThreadPool(1000);
        schedule = pool.scheduleWithFixedDelay(this::cleanCache,
                0, 200, TimeUnit.MILLISECONDS);
        thread = new Thread(this::cleanCacheAll);
        Runtime.getRuntime().addShutdownHook(thread);

    }
    public void stopSchedule(){
        Runtime.getRuntime().removeShutdownHook(thread);
        Optional.ofNullable(schedule)
                .ifPresent(s->s.cancel(true));
    }
    private void cleanCacheAll(){
        data.values().forEach(it->{
            Optional.ofNullable(it)
                    .map(KCacheItem::getClearCallBack)
                    .ifPresent(call-> call.accept(it.getValue()));
        });
    }
    protected void cleanCache(){
        long now = System.currentTimeMillis();
        ArrayList<String> removeList = new ArrayList<>(data.size());
        for (Map.Entry<String, KCacheItem> entry : data.entrySet()) {
            if (entry.getValue().getExpireTime() > 0 && entry.getValue().getExpireTime() < now){
                removeList.add(entry.getKey());
            }
        }
        System.out.println("clean -->"+removeList.size());
        removeList.forEach(it->{
            KCacheItem item = data.remove(it);
            System.out.println("->"+item);
            //如果存在回调 则执行回调
            Optional.ofNullable(item)
                    .map(KCacheItem::getClearCallBack)
                    .ifPresent(call-> call.accept(item.getValue()));
        });
    }
    public <T>void put(String key,T val){
        data.put(key,new KCacheItem<>(val));
    }
    public <T>void put(String key,T val,Long second){
        data.put(key,new KCacheItem<>(val,System.currentTimeMillis()+1000*second));
    }

    public <T>KCacheItem<T> putOrGet(String key,T initVal,int second){
        KCacheItem<T> item = new KCacheItem<>(initVal);
        item.setExpireTime(System.currentTimeMillis()+second*1000);
        return data.putIfAbsent(key,item);
    }

    public boolean expire(String key,Long second){
        return Optional.ofNullable(getItem(key))
                .map(it->{
                    it.setExpireTime(System.currentTimeMillis()+1000*second);
                    return true;
                }).orElse(false);

    }
    public <T> T expireGet(String key,Long second){
        return Optional.ofNullable((KCacheItem<T>)getItem(key))
                .map(it->{
                    it.setExpireTime(System.currentTimeMillis()+1000*second);
                    return it.getValue();
                }).orElse(null);
    }
    private KCacheItem getItem(String key){
        return Optional.ofNullable(data.get(key))
                .filter(it -> it.expireTime == -1 || it.expireTime >= System.currentTimeMillis())
                .orElseGet(()->{
                    data.remove(key);
                    return null;
                });
    }
    public <T> T get(String key){
        T val = Optional.ofNullable((KCacheItem<T>)getItem(key))
                .map(it -> it.getValue())
                .orElse(null);
        return val;
    }

    public static class KCacheItem<T> {
        private T value;
        private Long expireTime;
        private Consumer<T> clearCallBack;

        public KCacheItem(T value, Long expireTime) {
            this.value = value;
            this.expireTime = expireTime;
        }

        public KCacheItem(T value, Long expireTime, Consumer<T> clearCallBack) {
            this.value = value;
            this.expireTime = expireTime;
            this.clearCallBack = clearCallBack;
        }

        /**
         * 永不过期
         * @param value
         */
        public KCacheItem(T value) {
            this(value,-1L);
        }

        public T getValue() {
            return value;
        }

        public void setValue(T value) {
            this.value = value;
        }

        public Long getExpireTime() {
            return expireTime;
        }

        public void setExpireTime(Long expireTime) {
            this.expireTime = expireTime;
        }

        public Consumer<T> getClearCallBack() {
            return clearCallBack;
        }

        public void setClearCallBack(Consumer<T> clearCallBack) {
            this.clearCallBack = clearCallBack;
        }

        @Override
        public String toString() {
            return "KCacheItem{" +
                    "value=" + value +
                    ", expireTime=" + expireTime +
                    ", clearCallBack=" + clearCallBack +
                    '}';
        }
    }
}

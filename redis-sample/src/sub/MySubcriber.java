package sub;

import java.util.concurrent.TimeUnit;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPubSub;

public class MySubcriber extends JedisPubSub implements Runnable {
	private String channelName;
	private Jedis jedis;
	private String name;
	private int wafCount = 0;
	private int ipsCount = 0;
	private int esmCount = 0;
	private long sTime;
	private long eTime;

	public MySubcriber(String sName, Jedis j, String channel) {
		channelName = channel;
		jedis = j;
		name = sName;
	}

	@Override
	public void run() {
		System.out.println("Subcriber " + name + " started...");
		jedis.subscribe(this, channelName);
	}

	@Override
	public void onMessage(String channel, String message) {
		// System.out.println("[" + name + "] Channel: " + channel + " --- Message:" +
		// message);
		// if (message.equals("QUIT")) {
		// this.unsubscribe();
		// }
		if (message.contains("logType=WAF")) {
			wafCount++;
		} else if (message.contains("logType=IPS")) {
			ipsCount++;
		} else if (message.contains("logType=ESM")) {
			esmCount++;
		}
		if (message.equals("QUIT")) {
			this.unsubscribe(channel);
		}

	}

	@Override
	public void onPMessage(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub

	}

	@Override
	public void onPSubscribe(String arg0, int arg1) {
		// TODO Auto-generated method stub

	}

	@Override
	public void onPUnsubscribe(String arg0, int arg1) {
		// TODO Auto-generated method stub

	}

	@Override
	public void onSubscribe(String arg0, int arg1) {
		// start measuring time
		sTime = System.nanoTime();

	}

	@Override
	public void onUnsubscribe(String arg0, int arg1) {
		eTime = System.nanoTime();
		System.out.println("******************[SUB " + name + "]*************");
		System.out.println("[SUB " + name + "] ESM:" + esmCount + " - IPS:" + ipsCount + " - WAF:" + wafCount);
		System.out.println("[SUB " + name + "]  Received time: "
				+ TimeUnit.SECONDS.convert(eTime - sTime, TimeUnit.NANOSECONDS) + "(secs)");
		System.out.println("******************[/SUB " + name + "]*************");

	}

}

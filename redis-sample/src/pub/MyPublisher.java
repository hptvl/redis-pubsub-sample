package pub;

import java.util.List;
import java.util.concurrent.TimeUnit;

import redis.clients.jedis.Jedis;

public class MyPublisher implements Runnable {
	private String channel;
	private Jedis jedis;
	private List<String> data;
	private String name;

	public MyPublisher(String pName, Jedis j, String channel) {
		this.channel = channel;
		this.jedis = j;
		this.name = pName;
	}

	@Override
	public void run() {
		System.out.println("Publisher " + name + " started...");
		int count = 0;
		long sTime = System.nanoTime();
		while (count < getData().size()) {
			jedis.publish(channel, getData().get(count));
			count++;
		}
		if (data.get(data.size() - 1).equals("QUIT")) {
			count--;
		}
		long eTime = System.nanoTime();
		System.out.println("******************[PUB " + name + "]*************");
		System.out.println("[PUB " + name + "] Msg count:" + count);
		System.out.println("[PUB " + name + "] Sending time:"
				+ TimeUnit.SECONDS.convert(eTime - sTime, TimeUnit.NANOSECONDS) + "(secs)");
		System.out.println("******************[/PUB " + name + "]*************");

	}

	public List<String> getData() {
		return data;
	}

	public void setData(List<String> data) {
		this.data = data;
	}

}

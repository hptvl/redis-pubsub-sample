import java.io.FileReader;
import java.io.Reader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import pub.MyPublisher;
import redis.clients.jedis.JedisPool;
import sub.MySubcriber;
import utils.ESMOntGeneralUtil;

public class Main {
	// public static final int MAX = 1000;
	public static String[] IPS_FIELDS = { "origin", "mgr_time", "logtype", "s_info", "s_port", "d_info", "d_port",
			"method", "product" };
	public static String[] WAF_FIELDS = { "origin", "mgr_time", "logtype", "s_info", "s_port", "d_info", "d_port",
			"attack" };
	// public static String[] ESM_FIELDS = { "seq", "stime", "etime", "rulename",
	// "origin", "origin_name", "s_info",
	// "s_port", "d_info", "d_port", "method" };
	public static String[] ESM_FIELDS = { "seq", "occur_time", "end_time", "rule_name", "log_src_ip", "log_src_name",
			"s_ip", "s_port", "d_ip", "d_port", "method" };

	// occur_time=0, end_time=1, rule_name=2, log_src_ip=3, log_src_name=4, s_ip=5,
	// s_port=6, d_ip=7, d_port=8, method=9
	public static ArrayList<String> parceCSVAlert(String path) throws Exception {
		ArrayList<String> ontList = new ArrayList<String>();

		Reader in = new FileReader(path);
		Iterable<CSVRecord> records = CSVFormat.RFC4180.withHeader(ESM_FIELDS).parse(in);
		SimpleDateFormat timeFormat = new SimpleDateFormat("MM/dd/YYYY HH:mm");
		String id = "esm_" + new SimpleDateFormat("yyyMMddHHmmss").format(new Date());
		for (CSVRecord record : records) {
			if (record.getRecordNumber() == 1) { // header
				continue;
			}
			Map obj = new HashMap<String, Object>();
			obj.put("id", id + "_" + record.getRecordNumber());
			obj.put("occurTime",
					ESMOntGeneralUtil.convertDateString2UnixtimeString(record.get(ESM_FIELDS[1]), timeFormat));
			obj.put("endTime",
					ESMOntGeneralUtil.convertDateString2UnixtimeString(record.get(ESM_FIELDS[2]), timeFormat));
			obj.put("logType", "ESM");
			obj.put("logSourceIP", record.get(ESM_FIELDS[4]));
			obj.put("logSourceName", record.get(ESM_FIELDS[5]));
			obj.put("sourceIP", record.get(ESM_FIELDS[6]));
			obj.put("sourcePort", record.get(ESM_FIELDS[7]));
			obj.put("destinationIP", record.get(ESM_FIELDS[8]));
			obj.put("destinationPort", record.get(ESM_FIELDS[9]));
			obj.put("method", record.get(ESM_FIELDS[10]));

			ontList.add(obj.toString());
		}

		in.close();
		return ontList;
	}

	public static ArrayList<String> parceCSVIPS(String path) throws Exception {
		ArrayList<String> ontList = new ArrayList<String>();

		Reader in = new FileReader(path);
		Iterable<CSVRecord> records = CSVFormat.RFC4180.withHeader(IPS_FIELDS).parse(in);

		String id = "ips_" + new SimpleDateFormat("yyyMMddHHmmss").format(new Date());
		for (CSVRecord record : records) {
			if (record.getRecordNumber() == 1) { // header
				continue;
			}
			Map ont = new HashMap<String, Object>();
			ont.put("id", id + "_" + record.getRecordNumber());

			ont.put("origin", record.get("origin"));
			ont.put("managerTime", ESMOntGeneralUtil.convertDateString2UnixtimeString(
					record.get("mgr_time").substring(0, 14), new SimpleDateFormat("yyyyMMddHHmmss")));

			ont.put("logType", record.get("logtype"));
			ont.put("sourceIP", record.get("s_info"));
			ont.put("sourcePort", record.get("s_port"));
			ont.put("destinationIP", record.get("d_info"));
			ont.put("destinationPort", record.get("d_port"));
			ont.put("method", record.get("method"));
			ont.put("product", record.get("product"));

			ontList.add(ont.toString());
		}

		in.close();
		return ontList;
	}

	// origin,mgr_time,logType,s_info,s_port,d_info,d_port,attack
	public static ArrayList<String> parceCSVWAF(String path) throws Exception {
		ArrayList<String> ontList = new ArrayList<String>();

		Reader in = new FileReader(path);
		Iterable<CSVRecord> records = CSVFormat.RFC4180.withHeader(WAF_FIELDS).parse(in);
		String id = "waf_" + new SimpleDateFormat("yyyMMddHHmmss").format(new Date());
		for (CSVRecord record : records) {
			if (record.getRecordNumber() == 1) { // header
				continue;
			}
			Map ont = new HashMap<String, Object>();

			ont.put("id", id + "_" + record.getRecordNumber());
			ont.put("origin", record.get("origin"));
			ont.put("managerTime", ESMOntGeneralUtil.convertDateString2UnixtimeString(
					record.get("mgr_time").substring(0, 14), new SimpleDateFormat("yyyyMMddHHmmss")));

			ont.put("logType", record.get("logtype"));
			ont.put("sourceIP", record.get("s_info"));
			ont.put("sourcePort", record.get("s_port"));
			ont.put("destinationIP", record.get("d_info"));
			ont.put("destinationPort", record.get("d_port"));
			ont.put("method", record.get("attack"));

			ontList.add(ont.toString());
		}

		in.close();
		return ontList;
	}

	public static List<String> parseData() throws Exception {
		String base = "./testfile";
		long sTime = System.nanoTime();
		ArrayList<String> objList = new ArrayList<String>();
		objList.addAll(parceCSVAlert(base + "/esm.csv"));
		objList.addAll(parceCSVIPS(base + "/ips.csv"));
		objList.addAll(parceCSVWAF(base + "/waf.csv"));
		long eTime = System.nanoTime();
		long elapsedTime = eTime - sTime;
		System.out.println("Number of obj:" + objList.size());
		System.out.println("Parsed Elapsed: " + elapsedTime + " nano seconds");
		System.out.println("Parsed Seconds: " + TimeUnit.SECONDS.convert(elapsedTime, TimeUnit.NANOSECONDS));
		sTime = System.nanoTime();
		return objList;
	}

	public static void main(String[] args) throws Exception {
		String url = "192.168.50.103";
		int port = 6379;
		String base = "./testfile";
		JedisPool pool = new JedisPool(url, port);
		//
		// parse data
		List esmData = parceCSVAlert(base + "/esm.csv");
		List ipsData = parceCSVIPS(base + "/ips.csv");
		List wafData = parceCSVWAF(base + "/waf.csv");

		// add exit message to largest data list
		ipsData.add("QUIT");

		MySubcriber sub1 = new MySubcriber("Sub 1", pool.getResource(), "channel1");
		MySubcriber sub2 = new MySubcriber("Sub 2", pool.getResource(), "channel1");
		Thread tS1 = new Thread(sub1);
		Thread tS2 = new Thread(sub2);

		MyPublisher pub1 = new MyPublisher("Pub 1", pool.getResource(), "channel1");
		MyPublisher pub2 = new MyPublisher("Pub 2", pool.getResource(), "channel1");
		MyPublisher pub3 = new MyPublisher("Pub 3", pool.getResource(), "channel1");
		pub1.setData(esmData);
		pub2.setData(ipsData);
		pub3.setData(wafData);

		Thread tP1 = new Thread(pub1);
		Thread tP2 = new Thread(pub2);
		Thread tP3 = new Thread(pub3);

		tS1.start();
		tS2.start();
		tP1.start();
		tP2.start();
		tP3.start();
	}

}

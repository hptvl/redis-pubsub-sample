package utils;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;

public class ESMOntGeneralUtil {
	public static final Long convertDateString2Unixtime(String date, DateFormat format) throws ParseException {
		Date d = format.parse(date);
		Long unixTime = (long) d.getTime() / 1000;

		return unixTime;
	}

	public static final String convertDateString2UnixtimeString(String date, DateFormat format) throws ParseException {

		return String.valueOf(ESMOntGeneralUtil.convertDateString2Unixtime(date, format));
	}
}

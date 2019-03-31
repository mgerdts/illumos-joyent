/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#define	DEBUG 1
#include "../common/getnetgrent.c"

struct {
	const char *sval;
	uint64_t ival;
} pos_tests[] = {
	{ "Unspecified seconds and/or minutes; no time zone implies UTC", 0 },
	{ "2019010100",			15463008000ULL },
	{ "201901010000",		15463008000ULL },
	{ "20190101000000",		15463008000ULL },

	{ "As above, but explicit UTC", 0 },
	{ "2019010100Z",		15463008000ULL },
	{ "201901010000Z",		15463008000ULL },
	{ "20190101000000Z",		15463008000ULL },

	{ "UTC by many names", 0 },
	{ "20190415181957",		15553523970ULL },
	{ "20190415181957Z",		15553523970ULL },
	{ "20190415181957+00",		15553523970ULL },
	{ "20190415181957+0000",	15553523970ULL },
	{ "20190415181957-00",		15553523970ULL },
	{ "20190415181957-0000",	15553523970ULL },

	/*
	 * Test data can be generated with gnu date on a system with a proper
	 * set of zoneinfo files.
	 *
	 *  $ env TZ=Pacific/Chatham date -d @1555332597 \
	 *	'+{ "%Y%m%d%H%M%S%z", %s0ULL },'
	 *  { "20190415221957+0930", 15553325970ULL },
	 *
	 * The @<secs> is 1/10 of the value in the second column.  Time zones to
	 * give reasonable coverage include the following.  DST may cause you to
	 * get different offsets with different days.
	 *
	 *   +1245 Pacific/Chatham
	 *   +0930 Australia/Adelaide
	 *   +0530 Asia/Kolkata
	 *   +0100 Europe/London
	 *   +0000 Atlantic/Reykjavik
	 *   -0500 America/Chicago
	 *   -0930 Pacific/Marquesas
	 *   -1100 Pacific/Midway
	 */

	{ "The same time at various spots around the globe", 0 },
	{ "20190416013457+1245",	15553325970ULL },
	{ "20190415221957+0930",	15553325970ULL },
	{ "20190415181957+0530",	15553325970ULL },
	{ "20190415134957+0100",	15553325970ULL },
	{ "20190415124957+0000",	15553325970ULL },
	{ "20190415074957-0500",	15553325970ULL },
	{ "20190415031957-0930",	15553325970ULL },
	{ "20190415014957-1100",	15553325970ULL },

	{ "Party like it was 1999!", 0 },
	{ "20000101134500+1345",	9466848000ULL },
	{ "20000101103000+1030",	9466848000ULL },
	{ "20000101053000+0530",	9466848000ULL },
	{ "20000101000000+0000",	9466848000ULL },
	{ "20000101000000+0000",	9466848000ULL },
	{ "19991231180000-0600",	9466848000ULL },
	{ "19991231143000-0930",	9466848000ULL },
	{ "19991231130000-1100",	9466848000ULL },

	{ "Hour offsets", 0 },
	{ "20190415181957-0300",	15553631970ULL },
	{ "20190415181957-03",		15553631970ULL },
	{ "20190415181957+0200",	15553451970ULL },
	{ "20190415181957+02",		15553451970ULL },
	{ "2019041518-0300",		15553620000ULL },
	{ "201904151800-0300",		15553620000ULL },
	{ "20190415180000-0300",	15553620000ULL },

	{ "Half-hour offsets", 0 },
	{ "20190415181957-0230",	15553613970ULL },
	{ "2019041518-0230",		15553602000ULL },
	{ "201904151800-0230",		15553602000ULL },
	{ "20190415180000-0230",	15553602000ULL },
	{ "20190415181957+0530",	15553325970ULL },
	{ "2019041518+0530",		15553314000ULL },
	{ "201904151800+0530",		15553314000ULL },
	{ "20190415180000+0530",	15553314000ULL },

	{ "Fractional seconds without offsets", 0 },
	{ "20190415181957.0",		15553523970ULL },
	{ "20190415181957.1",		15553523971ULL },
	{ "20190415181957.2",		15553523972ULL },
	{ "20190415181957.3",		15553523973ULL },
	{ "20190415181957.4",		15553523974ULL },
	{ "20190415181957.5",		15553523975ULL },
	{ "20190415181957.6",		15553523976ULL },
	{ "20190415181957.7",		15553523977ULL },
	{ "20190415181957.8",		15553523978ULL },
	{ "20190415181957.9",		15553523979ULL },

	{ "Fractional minutes (0.1 minute is 6 seconds)", 0 },
	{ "201904151819.0",		15553523400ULL },
	{ "201904151819.1",		15553523460ULL },
	{ "201904151819.2",		15553523520ULL },
	{ "201904151819.3",		15553523580ULL },
	{ "201904151819.4",		15553523640ULL },
	{ "201904151819.5",		15553523700ULL },
	{ "201904151819.6",		15553523760ULL },
	{ "201904151819.7",		15553523820ULL },
	{ "201904151819.8",		15553523880ULL },
	{ "201904151819.9",		15553523940ULL },

	{ "Fractional hours (0.1 hour is 360 seconds)", 0 },
	{ "2019041518.0",		15553512000ULL },
	{ "2019041518.1",		15553515600ULL },
	{ "2019041518.2",		15553519200ULL },
	{ "2019041518.3",		15553522800ULL },
	{ "2019041518.4",		15553526400ULL },
	{ "2019041518.5",		15553530000ULL },
	{ "2019041518.6",		15553533600ULL },
	{ "2019041518.7",		15553537200ULL },
	{ "2019041518.8",		15553540800ULL },
	{ "2019041518.9",		15553544400ULL },

	{ "Fractions with offsets", 0 },
	{ "20190415181957.1-0300",	15553631971ULL },
	{ "20190415181957.2-03",	15553631972ULL },
	{ "20190415181957.3+0200",	15553451973ULL },
	{ "20190415181957.4+02",	15553451974ULL },
	{ "2019041518.5-0300",		15553638000ULL },
	{ "201904151800.5-0300",	15553620300ULL },
	{ "20190415180000.5-0300",	15553620005ULL },

	{ "Fractions with commas", 0 },
	{ "20190415181957,3",		15553523973ULL },
	{ "201904151819,7",		15553523820ULL },
	{ "2019041518,4",		15553526400ULL },
	{ "20190415181957,1-0300",	15553631971ULL },
};


struct {
	const char *sval;
	const char *desc;
} neg_tests[] = {
	{ "1969123100",		"Before the beginning of time" },
	{ "2019131518",		"Invalid month" },
	{ "2019020018",		"Invalid day (00); parse fails" },
	{ "2019013218",		"Invalid day (Jan 32); parse fails" },
	{ "2019040124",		"Invalid hour (24); parse fails" },
	{ "201904012360",	"Invalid minute (60); parse fails" },
	{ "20190401233061"	"Invalid second (61); parse fails" },
	{ "20190416013457+24",	"Offset hours too large" },
	{ "20190416013457+0160", "Offset minutes too large" },
	{ "201904151819.10",	"Too many fractional digits" },
	{ "2019041518.8.8",	"Too many decimals" },
	{ " 2019041518",	"Leading white space" },
	{ "2019041518 ",	"Trailing white space" },
	{ "2019041518ZZ",	"Zulu Zulu" },
	{ "2019041518z",	"Not the zed you are looking for" },
	{ "2020-01-04T14:23Z",	"Illegal characters (hyphen)" },
	{ "20200104T14:23Z",	"Illegal characters (T)" },
	{ "2020010414:23Z",	"Illegal characters (colon)" },
	{ "2020010414.",	"Decimal (period) with no digit" },
	{ "2020010414,",	"Decimal (comma) with no digit" },
	{ "202001041",		"Invalid minute (1 digit)" },
	{ "20200401120000+EDT",	"Illegal timezone, not offset" },
};

int
main(void)
{
	int i;
	uint64_t when;
	int err;
	uint32_t pass = 0;
	uint32_t fail = 0;

	for (i = 0; i < ARRAY_SIZE(pos_tests); i++) {
		const char *sval = pos_tests[i].sval;
		uint64_t ival = pos_tests[i].ival;

		if (ival == 0) {
			(void) printf("\n%s\n", sval);
			continue;
		}
		err = parse_generalized_time(sval, &when);
		if (err != 0) {
			(void) printf("*FAIL pos_tests[%d] %s parse error %d\n",
			    i, sval, err);
			fail++;
			continue;
		}
		if (when != ival) {
			(void) printf("*FAIL pos_tests[%d] %-22s expected %llu "
			    "got %llu\n", i, sval, ival, when);
			fail++;
			continue;
		}
		(void) printf(" PASS pos_tests[%d] %-22s => %llu\n", i, sval,
		    when);
		pass++;
	}

	(void) printf("\n\nNegative tests\n");
	for (i = 0; i < ARRAY_SIZE(neg_tests); i++) {
		const char *sval = neg_tests[i].sval;
		const char *desc = neg_tests[i].desc;

		when = 12345678987654321ULL;
		err = parse_generalized_time(sval, &when);
		if (err == 0) {
			(void) printf("*FAIL neg_tests[%d] %s parse succeeded "
			    "(%llu): %s\n", i, sval, when, desc);
			fail++;
		} else {
			(void) printf(" PASS neg_tests[%d] %s: %s\n\n",
			    i, sval, desc);
			pass++;
		}
	}

	printf("\nSummary:\n");
	printf("  PASS: %3d/%d\n", pass, pass + fail);
	printf("  FAIL: %3d/%d\n", fail, pass + fail);

	return (fail == 0 ? 0 : 1);
}

/*
 * dvbepg_json - dump dvb epg info in json
 * DVB code Mercilessly ripped off from dvddate
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/dvb/dmx.h>
#include "si_tables.h"
#include "dvbepg_json.h"

#define DEBUG(x) 

#define  _MPEG_PACKET_SIZE_ 188
#define  _MPEG_PACKET_SYNC_ 0x47
#define  _DVB_SDT_PID_ 0x11
#define  _DVB_EIT_PID_  0x12

FILE *out;
static char *ProgName;
static char *demux = "/dev/dvb/adapter0/demux0";

static int timeout  = 10;
static int packet_count = 0;
static int programme_count = 0;
static int update_count  = 0;
static int crcerr_count  = 0;
static int time_offset   = 0;
static int invalid_date_count = 0;
static int chan_filter	     = 0;
static int chan_filter_mask = 0;
static bool ignore_bad_dates = true;
static bool ignore_updates = true;
static bool silent = false;
static bool stream = false;
static char *udp_ip;
static unsigned short udp_port=0;
static int udp_sock;
static struct sockaddr_in udp_addr;
static unsigned int udp_addrlen;

typedef struct chninfo {
	struct chninfo *next;
	int sid;
	int eid;
	int ver;
} chninfo_t;

static struct chninfo *channels;
static void finish_up();

void  ALARMhandler(int sig)
{
  signal(SIGALRM, SIG_IGN);          /* ignore this signal       */
	finish_up();
  signal(SIGALRM, ALARMhandler);     /* reinstall the handler    */
}
static void dump(unsigned char *data,int len)
{
  for(int i=0; i < len; i++) {
    DEBUG(fprintf(stderr,"%02x ",data[i]));
    if((i > 0) && ((i % 16) == 0)) {
      DEBUG(fprintf(stderr,"\n\r"));
    }  
  }
  DEBUG(fprintf(stderr,"\n\r"));
}

/* Print usage information. {{{ */
static void usage() {
	fprintf(stderr, "Usage: %s [-d] [-u] [-c] [-n|m|p] [-s] [-t timeout]\n"
		"\t[-e encoding] [-o offset] [-i file] [-f file]\n\n"
		"\t-i file - Read from file/device instead of %s\n"
		"\t-f file - Write output to file instead of stdout\n"
		"\t-t timeout - Stop after timeout seconds of no new data\n"
		"\t-o offset  - time offset in hours from -12 to 12\n"
		"\t-c - Use Channel Identifiers from file 'chanidents'\n"
		"\t     (rather than sidnumber.dvb.guide)\n"
		"\t-d - output invalid dates\n"
		"\t-n - now next info only\n"
		"\t-m - current multiplex now_next only\n"
		"\t-p - other multiplex now_next only\n"
		"\t-s - stream input\n"
		"\t-u ip:port - UDP multicast input\n"
		"\t-e encoding - Use other than ISO-6937 default encoding\n"
		"\n", ProgName, demux);
	_exit(1);
} /*}}}*/

/* Print progress indicator. {{{ */
static void status() {
	if (!silent) {
		fprintf(stderr, "\r Status: %d pkts, %d prgms, %d updates, %d invalid, %d CRC err",
				packet_count, programme_count, update_count, invalid_date_count, crcerr_count);
	}
} /*}}}*/
void printCommaNewline()  {
    printf(",\n");
}
/* Parse command line arguments. {{{ */
static int do_options(int arg_count, char **arg_strings) {
	static const struct option Long_Options[] = {
		{"help", 0, 0, 'h'},
		{"timeout", 1, 0, 't'},
		{0, 0, 0, 0}
	};
	int Option_Index = 0;
	int fd;

	while (1) {
		int c = getopt_long(arg_count, arg_strings, "u:dsmpnht:o:f:i:e:", Long_Options, &Option_Index);
		if (c == EOF)
			break;
		switch (c) {
		case 'i':
			demux = strcmp(optarg, "-") ? optarg : NULL;
			break;
		case 'f':
			if ((fd = open(optarg, O_CREAT | O_TRUNC | O_WRONLY, 0666)) < 0) {
				fprintf(stderr, "%s: Can't write file %s\n", ProgName, optarg);
				usage();
			}
			dup2(fd, STDOUT_FILENO);
			close(fd);
			break;
		case 't':
			timeout = atoi(optarg);
			if (0 == timeout) {
				fprintf(stderr, "%s: Invalid timeout value\n", ProgName);
				usage();
			}
			break;
		case 'o':
			time_offset = atoi(optarg);
			if ((time_offset < -12) || (time_offset > 12)) {
				fprintf(stderr, "%s: Invalid time offset\n", ProgName);
				usage();
			}
			break;
		case 'u':
      {
        char *ip = strtok(optarg, ":");
        if(ip) {
          udp_ip=strdup(ip);
          udp_port = atoi(strtok(NULL, ":"));
        }
   //			ignore_updates = false;
      }
			break;
		case 'd':
			ignore_bad_dates = false;
			break;
		case 'n':
			chan_filter = 0x4e;
			chan_filter_mask = 0xfe;
			break;
		case 'm':
			chan_filter = 0x4e;
			chan_filter_mask = 0xff;
			break;
		case 'p':
			chan_filter = 0x4f;
			chan_filter_mask = 0xff;
			break;
		case 's':
			stream = true;
			break;
		case 'e':
			iso6937_encoding = optarg;
			break;
		case 'h':
		case '?':
			usage();
			break;
		case 0:
		default:
			fprintf(stderr, "%s: unknown getopt error - returned code %02x\n", ProgName, c);
			_exit(1);
		}
	}
	return 0;
} /*}}}*/

/* Lookup channel-id. {{{ */
static char *get_channelident(int chanid) {
	static char returnstring[256];

	sprintf(returnstring, "%d", chanid);
	return returnstring;
} /*}}}*/

/* Parse language-id translation file. {{{ */
static char *xmllang(u_char *l) {
	static union lookup_key lang;
	lang.c[0] = (char)l[0];
	lang.c[1] = (char)l[1];
	lang.c[2] = (char)l[2];
	lang.c[3] = '\0';

	char *c = lookup(languageid_table, lang.i);
	return c ? c : lang.c;
} /*}}}*/

/* Parse 0x4D Short Event Descriptor. {{{ */
enum ER { TITLE, SUB_TITLE };
static void parseEventDescription(void *data, enum ER round) {
	assert(GetDescriptorTag(data) == 0x4D);
	struct descr_short_event *evtdesc = data;
	char evt[256];
	char dsc[256];

	int evtlen = evtdesc->event_name_length;
	if (round == TITLE) {
		if (!evtlen)
			return;
		assert(evtlen < sizeof(evt));
		memcpy(evt, (char *)&evtdesc->data, evtlen);
		evt[evtlen] = '\0';
        printCommaNewline();
		printf("\t\t\"title\":{\n\t\t\t\"lang\":\"%s\",\n\t\t\t\"text\":\"%s\"\n\t\t}", xmllang(&evtdesc->lang_code1), jsonify(evt));
		return;
	}

	if (round == SUB_TITLE) {
		int dsclen = evtdesc->data[evtlen];
		assert(dsclen < sizeof(dsc));
		memcpy(dsc, (char *)&evtdesc->data[evtlen+1], dsclen);
		dsc[dsclen] = '\0';

		if (*dsc) {
			char *d = jsonify(dsc);
			if (d && *d) {
                printCommaNewline();
				printf("\t\t\"subtitle\":{\n\t\t\t\"lang\":\"%s\",\n\t\t\t\"text\":\"%s\"\n\t\t}", xmllang(&evtdesc->lang_code1), d);
            }
        }
	}
} /*}}}*/

/* Parse 0x4E Extended Event Descriptor. {{{ */
void parseLongEventDescription(void *data) {
	assert(GetDescriptorTag(data) == 0x4E);
	struct descr_extended_event *levt = data;
	char dsc[256];
	bool non_empty = (levt->descriptor_number || levt->last_descriptor_number || levt->length_of_items || levt->data[0]);

	if (non_empty && levt->descriptor_number == 0) {
        printCommaNewline();
		printf("\t\t\"desc\": {\n\t\t\t\"lang\":\"%s\",\n\t\t\t\"text\":\"", xmllang(&levt->lang_code1));
    }
	void *p = &levt->data;
	void *data_end = data + DESCR_GEN_LEN + GetDescriptorLength(data);
	while (p < (void *)levt->data + levt->length_of_items) {
		struct item_extended_event *name = p;
		int name_len = name->item_description_length;
		assert(p + ITEM_EXTENDED_EVENT_LEN + name_len < data_end);
		assert(name_len < sizeof(dsc));
		memcpy(dsc, (char *)&name->data, name_len);
		dsc[name_len] = '\0';
		printf("%s<br>", jsonify(dsc));

		p += ITEM_EXTENDED_EVENT_LEN + name_len;

		struct item_extended_event *value = p;
		int value_len = value->item_description_length;
		assert(p + ITEM_EXTENDED_EVENT_LEN + value_len < data_end);
		assert(value_len < sizeof(dsc));
		memcpy(dsc, (char *)&value->data, value_len);
		dsc[value_len] = '\0';
		printf("%s<br>", jsonify(dsc));

		p += ITEM_EXTENDED_EVENT_LEN + value_len;
	}
	struct item_extended_event *text = p;
	int len = text->item_description_length;
	if (non_empty && len) {
		assert(len < sizeof(dsc));
		memcpy(dsc, (char *)&text->data, len);
		dsc[len] = '\0';
		printf("%s", jsonify(dsc));
	}

	//printf("/%d/%d/%s", levt->descriptor_number, levt->last_descriptor_number, jsonify(dsc));
	if (non_empty && levt->descriptor_number == levt->last_descriptor_number)
		printf("\"\n\t\t}\n");
} /*}}}*/

/* Parse 0x50 Component Descriptor.  {{{
   video is a flag, 1=> output the video information, 0=> output the
   audio information.  seen is a pointer to a counter to ensure we
   only output the first one of each (XMLTV can't cope with more than
   one) */
enum CR { LANGUAGE, VIDEO, AUDIO, SUBTITLES };
static void parseComponentDescription(void *data, enum CR round, int *seen) {
	assert(GetDescriptorTag(data) == 0x50);
	struct descr_component *dc = data;
	char buf[256];

	int len = dc->descriptor_length;
	assert(len < sizeof(buf));
	memcpy(buf, (char *)&dc->data, len);
	buf[len] = '\0';

	switch (dc->stream_content) {
		case 0x01: // Video Info
			if (round == VIDEO && !*seen) {
				//if ((dc->component_type-1)&0x08) //HD TV
				//if ((dc->component_type-1)&0x04) //30Hz else 25
#if 0 //JCB
				printf("\t<video>\n");
				printf("\t\t<aspect>%s</aspect>\n", lookup(aspect_table, (dc->component_type-1) & 0x03));
				printf("\t</video>\n");
#endif
				(*seen)++;
			}
			break;
		case 0x02: // Audio Info
			if (round == AUDIO && !*seen) {
#if 0 //JCB
				printf("\t<audio>\n");
				printf("\t\t<stereo>%s</stereo>\n", lookup(audio_table, (dc->component_type)));
				printf("\t</audio>\n");
#endif
				(*seen)++;
			}
#if 0 //JCB
			if (round == LANGUAGE) {
				if (!*seen)
					printf("\t<language>%s</language>\n", xmllang(&dc->lang_code1));
				else
					printf("\t<!--language>%s</language-->\n", xmllang(&dc->lang_code1));
				(*seen)++;
			}
#endif
			break;
		case 0x03: // Teletext Info
			if (round == SUBTITLES) {
			// FIXME: is there a suitable XMLTV output for this?
			// if ((dc->component_type)&0x10) //subtitles
			// if ((dc->component_type)&0x20) //subtitles for hard of hearing
#if 0 //JCB
				printf("\t<subtitles type=\"teletext\">\n");
				printf("\t\t<language>%s</language>\n", xmllang(&dc->lang_code1));
				printf("\t</subtitles>\n");
#endif
			}
			break;
			// case 0x04: // AC3 info
	}
#if 0
	printf("\t<StreamComponent>\n");
	printf("\t\t<StreamContent>%d</StreamContent>\n", dc->stream_content);
	printf("\t\t<ComponentType>%x</ComponentType>\n", dc->component_type);
	printf("\t\t<ComponentTag>%x</ComponentTag>\n", dc->component_tag);
	printf("\t\t<Length>%d</Length>\n", dc->component_tag, dc->descriptor_length-6);
	printf("\t\t<Language>%s</Language>\n", lang);
	printf("\t\t<Data>%s</Data>\n", buf);
	printf("\t</StreamComponent>\n");
#endif
} /*}}}*/

static inline void set_bit(int *bf, int b) {
	int i = b / 8 / sizeof(int);
	int s = b % (8 * sizeof(int));
	bf[i] |= (1 << s);
}

static inline bool get_bit(int *bf, int b) {
	int i = b / 8 / sizeof(int);
	int s = b % (8 * sizeof(int));
	return bf[i] & (1 << s);
}

/* Parse 0x54 Content Descriptor. {{{ */
static void parseContentDescription(void *data) {
#if 0 //JCB
	assert(GetDescriptorTag(data) == 0x54);
	struct descr_content *dc = data;
	int once[256/8/sizeof(int)] = {0,};
	void *p;
	for (p = &dc->data; p < data + dc->descriptor_length; p += NIBBLE_CONTENT_LEN) {
		struct nibble_content *nc = p;
		int c1 = (nc->content_nibble_level_1 << 4) + nc->content_nibble_level_2;
#ifdef CATEGORY_UNKNOWN
		int c2 = (nc->user_nibble_1 << 4) + nc->user_nibble_2;
#endif
		if (c1 > 0 && !get_bit(once, c1)) {
			set_bit(once, c1);
			char *c = lookup(description_table, c1);
			if (c) {
				if (c[0]) {
					printf("\t<category>%s</category>\n", c);
                }
#ifdef CATEGORY_UNKNOWN
				else {
					printf("\t<!--category>%s %02X %02X</category-->\n", c+1, c1, c2);
                }
            }
			else {
				printf("\t<!--category>%02X %02X</category-->\n", c1, c2);
            }
#endif

		}
		// This is weird in the uk, they use user but not content, and almost the same values
	}
#endif
} /*}}}*/

/* Parse 0x55 Rating Descriptor. {{{ */
void parseRatingDescription(void *data) {
	assert(GetDescriptorTag(data) == 0x55);
	struct descr_parental_rating *pr = data;
	void *p;
	for (p = &pr->data; p < data + pr->descriptor_length; p += PARENTAL_RATING_ITEM_LEN) {
		struct parental_rating_item *pr = p;
		switch (pr->rating) {
			case 0x00: /*undefined*/
				break;
			case 0x01 ... 0x0F:
#if 0 //JCB
				printf("\t<rating system=\"dvb\">\n");
				printf("\t\t<value>%d</value>\n", pr->rating + 3);
				printf("\t</rating>\n");
#endif
				break;
			case 0x10 ... 0xFF: /*broadcaster defined*/
				break;
		}
	}
} /*}}}*/

/* Parse 0x5F Private Data Specifier. {{{ */
int parsePrivateDataSpecifier(void *data) {
	assert(GetDescriptorTag(data) == 0x5F);
	return GetPrivateDataSpecifier(data);
} /*}}}*/

/* Parse 0x76 Content Identifier Descriptor. {{{ */
/* See ETSI TS 102 323, section 12 */
void parseContentIdentifierDescription(void *data) {
	assert(GetDescriptorTag(data) == 0x76);
	struct descr_content_identifier *ci = data;
	void *p;
	for (p = &ci->data; p < data + ci->descriptor_length; /* at end */) {
		struct descr_content_identifier_crid *crid = p;
		struct descr_content_identifier_crid_local *crid_data;

		int crid_length = 3;

		char type_buf[32];
		char *type;
		char buf[256];

		type = lookup(crid_type_table, crid->crid_type);
		if (type == NULL)
		{
			type = type_buf;
			sprintf(type_buf, "0x%2x", crid->crid_type);
		}

		switch (crid->crid_location)
		{
		case 0x00: /* Carried explicitly within descriptor */
			crid_data = (descr_content_identifier_crid_local_t *)&crid->crid_ref_data;
			int cridlen = crid_data->crid_length;
			assert(cridlen < sizeof(buf));
			memcpy(buf, (char *)&crid_data->crid_byte, cridlen);
			buf[cridlen] = '\0';
#if 0
			printf("\t<crid type='%s'>%s</crid>\n", type, jsonify(buf));
#endif
			crid_length = 2 + crid_data->crid_length;
			break;
		case 0x01: /* Carried in Content Identifier Table (CIT) */
			break;
		default:
			break;
		}

		p += crid_length;
	}
} /*}}}*/

/* Parse Descriptor. {{{
 * Tags should be output in this order:

'title', 'sub-title', 'desc', 'credits', 'date', 'category', 'language',
'orig-language', 'length', 'icon', 'url', 'country', 'episode-num',
'video', 'audio', 'previously-shown', 'premiere', 'last-chance',
'new', 'subtitles', 'rating', 'star-rating'
*/
static void parseDescription(void *data, size_t len) {
	int round, pds = 0;

	for (round = 0; round < 8; round++) {
		int seen = 0; // no title/language/video/audio/subtitles seen in this round
		void *p;
		for (p = data; p < data + len; p += DESCR_GEN_LEN + GetDescriptorLength(p)) {
			struct descr_gen *desc = p;
			switch (GetDescriptorTag(desc)) {
				case 0:
					break;
				case 0x4D: //short evt desc, [title] [sub-title]
					// there can be multiple language versions of these
					if (round == 0) {
						parseEventDescription(desc, TITLE);
					}
					else if (round == 1)
						parseEventDescription(desc, SUB_TITLE);
					break;
				case 0x4E: //long evt descriptor [desc]
					if (round == 2)
						parseLongEventDescription(desc);
					break;
				case 0x50: //component desc [language] [video] [audio] [subtitles]
					if (round == 4)
						parseComponentDescription(desc, LANGUAGE, &seen);
					else if (round == 5)
						parseComponentDescription(desc, VIDEO, &seen);
					else if (round == 6)
						parseComponentDescription(desc, AUDIO, &seen);
					else if (round == 7)
						parseComponentDescription(desc, SUBTITLES, &seen);
					break;
				case 0x53: // CA Identifier Descriptor
					break;
				case 0x54: // content desc [category]
					if (round == 3)
						parseContentDescription(desc);
					break;
				case 0x55: // Parental Rating Descriptor [rating]
					if (round == 7)
						parseRatingDescription(desc);
					break;
				case 0x5f: // Private Data Specifier
					pds = parsePrivateDataSpecifier(desc);
					break;
				case 0x64: // Data broadcast desc - Text Desc for Data components
					break;
				case 0x69: // Programm Identification Label
					break;
				case 0x81: // TODO ???
					if (pds == 5) // ARD_ZDF_ORF
						break;
				case 0x82: // VPS (ARD, ZDF, ORF)
					if (pds == 5) // ARD_ZDF_ORF
						// TODO: <programme @vps-start="???">
						break;
				case 0x4F: // Time Shifted Event
				case 0x52: // Stream Identifier Descriptor
				case 0x5E: // Multi Lingual Component Descriptor
				case 0x83: // Logical Channel Descriptor (some kind of news-ticker on ARD-MHP-Data?)
				case 0x84: // Preferred Name List Descriptor
				case 0x85: // Preferred Name Identifier Descriptor
				case 0x86: // Eacem Stream Identifier Descriptor
					break;
				case 0x76: // Content identifier descriptor
					if (round == 5)
						parseContentIdentifierDescription(desc);
					break;
				default:
					if (round == 0) {
						fprintf(stderr,"\t<!--Unknown_Please_Report ID=\"%x\" Len=\"%d\" -->\n", GetDescriptorTag(desc), GetDescriptorLength(desc));
                    }
			}
		}
	}
} /*}}}*/

/* Check that program has at least a title as is required by xmltv.dtd. {{{ */
static bool validateDescription(void *data, size_t len) {
	void *p;
	for (p = data; p < data + len; p += DESCR_GEN_LEN + GetDescriptorLength(p)) {
		struct descr_gen *desc = p;
		if (GetDescriptorTag(desc) == 0x4D) {
			struct descr_short_event *evtdesc = p;
			// make sure that title isn't empty
			if (evtdesc->event_name_length) return true;
		}
	}
	return false;
} /*}}}*/

/* Use the routine specified in ETSI EN 300 468 V1.4.1, {{{
 * "Specification for Service Information in Digital Video Broadcasting"
 * to convert from Modified Julian Date to Year, Month, Day. */
static void parseMJD(long int mjd, struct tm *t) {
	int year = (int) ((mjd - 15078.2) / 365.25);
	int month = (int) ((mjd - 14956.1 - (int) (year * 365.25)) / 30.6001);
	int day = mjd - 14956 - (int) (year * 365.25) - (int) (month * 30.6001);
	int i = (month == 14 || month == 15) ? 1 : 0;
	year += i ;
	month = month - 2 - i * 12;

	t->tm_mday = day;
	t->tm_mon = month;
	t->tm_year = year;
	t->tm_isdst = -1;
	t->tm_wday = t->tm_yday = 0;
} /*}}}*/

/* Parse Event Information Table. {{{ */
static void parseEIT(void *data, size_t len) {
	struct eit *e = data;
	void *p;
	struct tm  dvb_time;
	char       date_strbuf[256];

	len -= 4; //remove CRC

	// For each event listing
	for (p = &e->data; p < data + len; p += EIT_EVENT_LEN + GetEITDescriptorsLoopLength(p)) {
		struct eit_event *evt = p;
		struct chninfo *c;
		// find existing information?
		for (c = channels; c != NULL; c = c->next) {
			// found it
			if (c->sid == HILO(e->service_id) && (c->eid == HILO(evt->event_id))) {
				if (c->ver <= e->version_number) // seen it before or its older FIXME: wrap-around to 0
					return;
				else {
					c->ver = e->version_number; // update outputted version
					update_count++;
					if (ignore_updates)
						return;
					break;
				}
			}
		}

		// its a new program
		if (c == NULL) {
			chninfo_t *nc = malloc(sizeof(struct chninfo));
			nc->sid = HILO(e->service_id);
			nc->eid = HILO(evt->event_id);
			nc->ver = e->version_number;
			nc->next = channels;
			channels = nc;
		}

		/* we have more data, refresh alarm */
		if (timeout) alarm(timeout);

		// No program info at end! Just skip it
		if (GetEITDescriptorsLoopLength(evt) == 0)
			return;

		parseMJD(HILO(evt->mjd), &dvb_time);

		dvb_time.tm_sec =  BcdCharToInt(evt->start_time_s);
		dvb_time.tm_min =  BcdCharToInt(evt->start_time_m);
		dvb_time.tm_hour = BcdCharToInt(evt->start_time_h) + time_offset;
		time_t start_time = timegm(&dvb_time);

		dvb_time.tm_sec  += BcdCharToInt(evt->duration_s);
		dvb_time.tm_min  += BcdCharToInt(evt->duration_m);
		dvb_time.tm_hour += BcdCharToInt(evt->duration_h);
		time_t stop_time = timegm(&dvb_time);

		time_t now;
		time(&now);
		// basic bad date check. if the program ends before this time yesterday, or two weeks from today, forget it.
		if ((difftime(stop_time, now) < -24*60*60) || (difftime(now, stop_time) > 14*24*60*60) ) {
			invalid_date_count++;
			if (ignore_bad_dates)
				return;
		}

		// a program must have a title that isn't empty
		if (!validateDescription(&evt->data, GetEITDescriptorsLoopLength(evt))) {
			return;
		}

        if(programme_count != 0) {
            printCommaNewline();
        }
		programme_count++;
		printf("\t{\n\t\t\"sid\":\"%s\"", get_channelident(HILO(e->service_id)));
        printCommaNewline();
		strftime(date_strbuf, sizeof(date_strbuf), "\t\t\"start\":\"%H:%M\"", localtime(&start_time) );
		printf("%s", date_strbuf);
        printCommaNewline();
		strftime(date_strbuf, sizeof(date_strbuf), "\t\t\"stop\":\"%H:%M\"", localtime(&stop_time));
		printf("%s", date_strbuf);
        printCommaNewline();
		printf("\t\t\"startTS\":\"%lu\"", start_time);
        printCommaNewline();
		printf("\t\t\"stopTS\":\"%lu\"", stop_time);

		//printf("\t<EventID>%i</EventID>\n", HILO(evt->event_id));
        printCommaNewline();
		printf("\t\t\"RunningStatus\":%i", evt->running_status);
        //0 undefined 1 not running 2 starts in a few seconds (e.g. for video recording) 3 pausing 4 running

		parseDescription(&evt->data, GetEITDescriptorsLoopLength(evt));
		printf("\n\t}");
	}
} /*}}}*/

/* Exit hook: close xml tags. {{{ */
static void finish_up() {
	if (!silent)
		fprintf(stderr, "\n");
	printf("\n\t]}\n");
	exit(0);
} /*}}}*/

/* Read EIT segments from DVB-demuxer or file. {{{ */
static void readEventTables(void) {
	int r, n = 0;
	char buf[1<<12], *bhead = buf;

	/* The dvb demultiplexer simply outputs individual whole packets (good),
	 * but reading captured data from a file needs re-chunking. (bad). */
	do {
		if (n < sizeof(struct si_tab))
			goto read_more;
		struct si_tab *tab = (struct si_tab *)bhead;
		if (GetTableId(tab) == 0)
			goto read_more;
		size_t l = sizeof(struct si_tab) + GetSectionLength(tab);
		if (n < l)
			goto read_more;
		packet_count++;
		if (_dvb_crc32((uint8_t *)bhead, l) != 0) {
			/* data or length is wrong. skip bytewise. */
			//l = 1; // FIXME
			crcerr_count++;
		} else
			parseEIT(bhead, l);
		status();
		/* remove packet */
		n -= l;
		bhead += l;
		continue;
read_more:
		/* move remaining data to front of buffer */
		if (n > 0)
			memmove(buf, bhead, n);
		/* fill with fresh data */
		r = read(STDIN_FILENO, buf+n, sizeof(buf)-n);
    fprintf(stderr,"read %d bytes\r\n",r);
		bhead = buf;
		n += r;
	} while (r > 0);
} /*}}}*/

/* Read EIT segments from DVB-demuxer or file. {{{ */
static void readEventTablesFromUDP(void) {
	int r,n=0;
  unsigned char buf[1<<12], *bhead = buf;
  unsigned char tsbuf[2048/*_MPEG_PACKET_SIZE_*/],*p;
  unsigned short pid;
  size_t l=0;
	do {
    r = recvfrom(udp_sock, tsbuf, sizeof(tsbuf), 0, 
		  (struct sockaddr *) &udp_addr, &udp_addrlen);
	  if (r < 0) {
  	  perror("recvfrom");
	    exit(1);
	  }
//    fprintf(stderr,"udp got %d bytes\n\r",r);
    n=0;
    p=tsbuf;
    do  {
  //    r = read(STDIN_FILENO,tsbuf,_MPEG_PACKET_SIZE_);
      packet_count++;
      if (p[0] !=   _MPEG_PACKET_SYNC_) {
        fprintf(stderr,"Sync byte failed %d\n\r",packet_count);
        dump(p,r);
        exit(-1);
      }

      pid = (p[1] & 0x1f << 8) | (p[2] & 0xff); // 13 bit
      if (pid == _DVB_EIT_PID_) {
        DEBUG(fprintf(stderr,"p is:\n\r"));
        dump(p,_MPEG_PACKET_SIZE_);
        if((p[1] & 0x40) == 0x40) { //payload start
            //process previous payload
            if(l > 0) { 
              bhead = buf+1;
              struct si_tab *tab = (struct si_tab *)bhead;
              l = sizeof(struct si_tab) + GetSectionLength(tab);
//	            fwrite(bhead,l,1,out);
              DEBUG(fprintf(stderr,"Buffer is:\n\r"));
              dump(bhead,l);
              if (_dvb_crc32((uint8_t *)bhead, l) != 0) {
                /* data or length is wrong. skip bytewise. */
                //l = 1; // FIXME
                crcerr_count++;
              } 
              else {
                parseEIT(bhead, l);
              }
            }
            l=0;
            bhead=buf;
        }
        memcpy(bhead,p+4,_MPEG_PACKET_SIZE_-4);
          
        bhead+=_MPEG_PACKET_SIZE_-4;
        l+=_MPEG_PACKET_SIZE_-4;
//        dump(buf,l);
      }
      p+=_MPEG_PACKET_SIZE_;
      n+=_MPEG_PACKET_SIZE_;
    } while (n < r);
	} while (r > 0);
#if 0
	/* The dvb demultiplexer simply outputs individual whole packets (good),
	 * but reading captured data from a file needs re-chunking. (bad). */
	do {
		if (n < sizeof(struct si_tab))
			goto read_more;
		struct si_tab *tab = (struct si_tab *)bhead;
		if (GetTableId(tab) == 0)
			goto read_more;
		size_t l = sizeof(struct si_tab) + GetSectionLength(tab);
		if (n < l)
			goto read_more;
		packet_count++;
		if (_dvb_crc32((uint8_t *)bhead, l) != 0) {
			/* data or length is wrong. skip bytewise. */
			//l = 1; // FIXME
			crcerr_count++;
		} else
        fprintf(stderr,"parse %d bytes\r\n",l);

			parseEIT(bhead, l);
		status();
		/* remove packet */
		n -= l;
		bhead += l;
		continue;
read_more:
		/* move remaining data to front of buffer */
		if (n > 0)
			memmove(buf, bhead, n);
		/* fill with fresh data */
		r = read(STDIN_FILENO, buf+n,188);
    fprintf(stderr,"read %d bytes\r\n",r);
		bhead = buf;
		n += r;
	} while (r > 0);
#endif
} /*}}}*/

/* Setup demuxer or open file as STDIN. {{{ */
static int openInput(void) {
	int fd_epg, to;
	struct stat stat_buf;

	if (demux == NULL)
		return 0; // Read from STDIN, which is open al

	if ((fd_epg = open(demux, O_RDWR)) < 0) {
		perror("fd_epg DEVICE: ");
		return -1;
	}

	if (fstat(fd_epg, &stat_buf) < 0) {
		perror("fd_epg DEVICE: ");
		return -1;
	}
	if (S_ISCHR(stat_buf.st_mode)) {
		bool found = false;
		struct dmx_sct_filter_params sctFilterParams = {
			.pid = 18, // EIT data
			.timeout = 0,
			.flags =  DMX_IMMEDIATE_START,
			.filter = {
				.filter[0] = chan_filter, // 4e is now/next this multiplex, 4f others
				.mask[0] = chan_filter_mask,
			},
		};

		if (ioctl(fd_epg, DMX_SET_FILTER, &sctFilterParams) < 0) {
			perror("DMX_SET_FILTER:");
			close(fd_epg);
			return -1;
		}

		for (to = timeout; to > 0; to--) {
			int res;
			struct pollfd ufd = {
				.fd = fd_epg,
				.events = POLLIN,
			};

			res = poll(&ufd, 1, 1000);
			if (0 == res) {
				fprintf(stderr, ".");
				fflush(stderr);
				continue;
			}
			if (1 == res) {
				found = true;
				break;
			}
			fprintf(stderr, "error polling for data\n");
			close(fd_epg);
			return -1;
		}
		fprintf(stderr, "\n");
		if (!found) {
			fprintf(stderr, "timeout - try tuning to a multiplex?\n");
			close(fd_epg);
			return -1;
		}

		signal(SIGALRM, finish_up);
		alarm(timeout);
	} else {
		// disable alarm timeout for normal files
		timeout = 0;
	}

	dup2(fd_epg, STDIN_FILENO);
	close(fd_epg);

	return 0;
} /*}}}*/

/* Main function. {{{ */
int main(int argc, char **argv) {
  out = fdopen(dup(fileno(stdout)), "wb");
  signal(SIGALRM, ALARMhandler);
  siginterrupt(SIGALRM, 1);
  /* Remove path from command */
	ProgName = strrchr(argv[0], '/');
	if (ProgName == NULL)
		ProgName = argv[0];
	else
		ProgName++;
	/* Process command line arguments */
	do_options(argc, argv);

	printf("{\n\t\"programs\":[\n");
  if(udp_ip)  {
    struct ip_mreq mreq;
    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
      perror("socket");
      exit(1);
    }
    memset((char *)&udp_addr, 0,sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_addr.sin_port = htons(udp_port);
    udp_addrlen = sizeof(udp_addr);

    /* receive */
    if (bind(udp_sock, (struct sockaddr *) &udp_addr, sizeof(udp_addr)) < 0) {        
      perror("bind");
      exit(1);
    }    
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);   
    
    mreq.imr_multiaddr.s_addr = inet_addr(udp_ip);         
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);         
    if (setsockopt(udp_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		  &mreq, sizeof(mreq)) < 0) {
	    perror("setsockopt mreq");
	    exit(1);
    }  
    readEventTablesFromUDP();
  }
  else {
    if (openInput() != 0) {
      fprintf(stderr, "Unable to get event data from multiplex.\n");
      exit(1);
    }	  
    readEventTables();
  }  
	finish_up();
	return 0;
} /*}}}*/
// vim: foldmethod=marker ts=4 sw=4


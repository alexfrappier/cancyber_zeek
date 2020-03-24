# CanCyber.org Zeek Module v2.1.01 2020 03 22

module cancyber_zeek;

@load ../config
@load ./cancyber_expire

@load-sigs ../signatures/cancyber_sigs.sig

@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load base/misc/version


redef Intel::item_expiration = 6.5hr;
redef ignore_checksums = T;

export {
	global NST_VERSION = "2.1.01";

	global MAX_HITS: int = 100;
	global MAX_DNS_HITS: int = 2;
	global MAX_SCAN_HITS: int = 2;

	global base_signature_url = fmt("https://tool.cancyber.org/get/indicators?toolkey=%s&zeekversion=%s&version=%s&query=", cancyber_zeek::APIKEY, Version::number, NST_VERSION);

	global signature_refresh_period = 6hr &redef;

	global load_signatures: function();
	global register_hit: function(hitvalue: string);

}



# Modelled on the original function from ActiveHTTP but they stripped out the newlines and joined
# everything together. Need to keep the original string vector to process individual lines.
# Original Source: https://github.com/zeek/zeek/blob/master/scripts/base/utils/active-http.zeek

function request2curl(r: ActiveHTTP::Request, bodyfile: string, headersfile: string): string
{
	local cmd = fmt("curl -s -L -g -o \"%s\" -D \"%s\" -X \"%s\"",
	                bodyfile,
	                headersfile,
	                r$method);

	cmd = fmt("%s -m %.0f", cmd, r$max_time);

	if ( r?$client_data )
		cmd = fmt("%s -d @-", cmd);

	if ( r?$addl_curl_args )
		cmd = fmt("%s %s", cmd, r$addl_curl_args);

	cmd = fmt("%s \"%s\"", cmd, r$url);
	# Make sure file will exist even if curl did not write one.
	cmd = fmt("%s && touch %s", cmd, bodyfile);
	return cmd;
}

function strings_request(req: ActiveHTTP::Request): string_vec
{
	local tmpfile     = "/tmp/zeek-activehttp-" + unique_id("");
	local bodyfile    = fmt("%s_body", tmpfile);
	local headersfile = fmt("%s_headers", tmpfile);

	local cmd = request2curl(req, bodyfile, headersfile);
	local stdin_data = req?$client_data ? req$client_data : "";
	
	return when ( local result = Exec::run([$cmd=cmd, $stdin=stdin_data, $read_files=set(bodyfile, headersfile)]) )
	{
		# If there is no response line then nothing else will work either.
		if ( ! (result?$files && headersfile in result$files) )
		{
			Reporter::error(fmt("There was a failure when requesting \"%s\" with ActiveHTTP.", req$url));
			print "WARNING: Active HTTP failed for: " + req$url;

			return vector();  # Empty string vector indicates failure
		}
		
		return result$files[bodyfile];
	}
}


# NOTE: These add item functions should only be called within zeek_init or inside one of the load functions
# There appears to be a race condition during setup such that these items may not be included in the expiry
# checks if executed too soon. Note that function call execution order may not be as it appears in the code
# due to possible asynchronous processing.

function add_cancyber_item_ext(sig: string, sig_type: Intel::Type, sig_desc: string, expires: interval) {
	local zero: int = 0;
	local cmeta : Intel::MetaData = [
		$source = "CanCyber",
		$do_notice = T,
		$cancyber_expire = expires,
		$desc = sig_desc,
		$cancyber_hits = zero,
		$cancyber_dns_hits = zero,
		$cancyber_scan_hits = zero


	];
	
	local item : Intel::Item = [
		$indicator = sig,
		$indicator_type = sig_type,
		$meta = cmeta
	];
	Intel::insert(item);
}

function add_cancyber_item(sig: string, sig_type: Intel::Type) {
	local zero: int = 0;
	local cmeta : Intel::MetaData = [
		$source = "CanCyber",
		$do_notice = T,
		$cancyber_expire = Intel::item_expiration,
		$cancyber_hits = zero,
		$cancyber_dns_hits = zero,
		$cancyber_scan_hits = zero
	];
	
	local item : Intel::Item = [
		$indicator = sig,
		$indicator_type = sig_type,
		$meta = cmeta
	];
	Intel::insert(item);
}


# CANCYBER SIGNATURE DOWNLOAD FUNCTIONS - these are now a single download.  Note that the Intel
# Framework stores all signature data with a to_lower applied so no need in this code. Note that
# line counts for signature downloads includes possible comments - output stored in stdout.log to
# be used for verification checking if necessary.

# Special option to load all the hash strings combined as a single file
function load_indicators() {
	local ns = get_net_stats();

	local request: ActiveHTTP::Request = [
		$url = fmt("%szeekone&ccsource=%s&pkts_dropped=%d&pkts_recvd=%d&pkts_link=%d&bytes_recvd=%d", base_signature_url, CCSOURCE, ns$pkts_dropped, ns$pkts_recvd, ns$pkts_link, ns$bytes_recvd), $max_time = 2 min
	];

	
    print "Downloading Indicators...";
	
    when ( local lines = strings_request(request) ) {
		if (|lines| > 0 ) {
			print "Processing Indicators...";
			print fmt("Number of Indicators %d", |lines|);
	
			local domaincnt = 0;
			local ipcnt = 0;
			local subnetcnt = 0;
			local urlcnt = 0;
			local softwarecnt = 0;
			local emailcnt = 0;
			local usercnt = 0;
			local hashcnt = 0;
			local filenamecnt = 0;
		
			
			for (line in lines) {
				local sig = strip(lines[line]);

				#local parts: string_array;
				local parts = split_string(sig, /\t/);



				if (|parts| > 3 && parts[0][0] != "#") {
					local zero: int = 0;
					local dh_meta : Intel::MetaData = [
						$source = "CanCyber",
						$do_notice = T,
						$cancyber_expire = Intel::item_expiration,
						$desc = parts[3],
						$url = parts[4],
						$cancyber_hits = zero,
						$cancyber_dns_hits = zero,
						$cancyber_scan_hits = zero
					];
					local item : Intel::Item = [
						$indicator = parts[0],
						$indicator_type = Intel::DOMAIN,
						$meta = dh_meta
					];


					if (parts[1] == "Intel::ADDR") {
						item$indicator_type = Intel::ADDR;
						ipcnt += 1;
					} else if (parts[1] == "Intel::SUBNET") {
						item$indicator_type = Intel::SUBNET;
						subnetcnt += 1;
					} else if (parts[1] == "Intel::URL") {
						item$indicator_type = Intel::URL;
						urlcnt += 1;
					} else if (parts[1] == "Intel::SOFTWARE") {
						item$indicator_type = Intel::SOFTWARE;
						softwarecnt += 1;
					} else if (parts[1] == "Intel::EMAIL") {
						item$indicator_type = Intel::EMAIL;
						emailcnt += 1;
					} else if (parts[1] == "Intel::USER_NAME") {
						item$indicator_type = Intel::USER_NAME;
						usercnt += 1;
					} else if (parts[1] == "Intel::CERT_HASH") {
						item$indicator_type = Intel::FILE_HASH; #cert hash isn't really implemented
						hashcnt += 1;
					} else if (parts[1] == "Intel::PUBKEY_HASH") {
						item$indicator_type = Intel::FILE_HASH;
						hashcnt += 1;
					} else if (parts[1] == "Intel::FILE_HASH") {
						item$indicator_type = Intel::FILE_HASH;
						hashcnt += 1;
					} else if (parts[1] == "Intel::FILE_NAME") {
						item$indicator_type = Intel::FILE_NAME;
						filenamecnt += 1;
					} else if (parts[1] == "Intel::DOMAIN")
						domaincnt += 1;
					else
						next;

					Intel::insert(item);
				}
			}

			print " Intel Indicator Counts:";
			print fmt("    Intel::DOMAIN:    %d", domaincnt);
			print fmt("    Intel::ADDR:        %d", ipcnt);
			print fmt("    Intel::URL:        %d", urlcnt);
			print fmt("    Intel::SUBNET:    %d", subnetcnt);
			print fmt("    Intel::SOFTWARE:  %d", softwarecnt);
			print fmt("    Intel::EMAIL:     %d", emailcnt);
			print fmt("    Intel::USER_NAME: %d", usercnt);
			print fmt("    Intel::FILE_HASH: %d", hashcnt);
			print fmt("    Intel::FILE_NAME: %d",filenamecnt);
			print "Finished Processing Indicators";


		} else {
			print "indicator download error";
		}
		flush_all();
    }
}





# Download updated version of source file that will be reloaded when Zeek is restarted
# No known method to dynamically add or trigger a reload of the source or signature files
# but this function will keep a new version ready and up to date.

function update_cancyber_source(fname: string, querytag: string) {
	local request: ActiveHTTP::Request = [
		$url = base_signature_url + querytag
	];
	
    local check = "find " + @DIR + "/" + fname + " -mmin +60 | egrep .";
    when ( local r = Exec::run([$cmd=check]) )
	{
        if (r$exit_code != 0) {
	    print "INFO: file is recent not updating: " + fname;
            return;
        }
        when ( local lines = strings_request(request) ) {
		if (|lines| > 0 && lines[0][0] == "#") {
			print "Updating File " + fname;
			
			# Directory variable appends period for some reason
			# but guard that it may not exist in future.
			local tmp_fname = @DIR + "/." + unique_id("cczeek");
			local final_fname = @DIR + "/" + fname;
			local f = open(tmp_fname);
			enable_raw_output(f);
			
			for (line in lines) {
				print f,lines[line] + "\n";
			}
			
			close(f);
			
			if (unlink(final_fname)) {

			} else {
				print "WARNING: Could not unlink file for code update: " + final_fname;
			}
			if (rename(tmp_fname,final_fname)) {
				print "Finished Updating File: " + fname;
			} else {
				print "ERROR: Could not rename tmp file for code update: " + tmp_fname;
			}

		} else {
			print "WARNING: Code update download failed for: " + fname;
		}
        }
    }
}


function register_hit(hitvalue: string) {
	local upload_hit_url = fmt("https://tool.cancyber.org/put/sightings?epstkey=%s&platform=normal&hcode=ZEK", cancyber_zeek::APIKEY);

   	local post_data: table[string] of string;
	post_data["platform"] = "normal";
	post_data["hcode"] = "ZEK";
	post_data["hvalue"] = hitvalue;
	
    local request: ActiveHTTP::Request = [
       $url=upload_hit_url,
	$method="POST",
	$client_data=to_json(post_data),
	$addl_curl_args = fmt("--header \"Content-Type: application/json\" --header \"Accept: application/json\"")
    ];
	
    when ( local resp = ActiveHTTP::request(request) ) {
		print "CanCyber Sighting: " + hitvalue;
		
		if (resp$code == 200) {
			print fmt("Sighting Result ===> %s", resp$body);
		} else {
			print fmt("Sighting FAILED ===> %s", resp);
		}
    }
	
}


function startup_intel() {
	# WARNING: network_time function seems to return 0 until after Zeek is fully initialized
	# Any intel expiry time added here is effectively useless so use either positive value to
	# expire on the next expiry check or negative to never expire.
	
	# IMPORTANT: Need at least one registered otherwise item_expired hook may not be called.
	# This fake intel item MUST be setup in order for the expiry feature to work properly.
	# The expiry hook seems to be removed before the load_signatures function is called
	# unless an item exists.
	add_cancyber_item_ext("ww.fakecancyberurl.zzz", Intel::DOMAIN, "important placeholder item", -1min);
	
	# FOR TESTING: add in extra intel items if desired noting expiry time issue above
	#add_cancyber_item_ext("www.google.com", Intel::DOMAIN, "test single intel item", -1min);
}


event do_reload_signatures() {
	if (zeek_is_terminating()) {
		print "Zeek Terminating - Cancelling Scheduled Signature Downloads";
	} else {
		load_signatures();
		schedule signature_refresh_period { do_reload_signatures() };
	}
}


function load_signatures() {
        print fmt("Refresh period is now %s", signature_refresh_period);
	print fmt("Downloading CanCyber Signatures %s", strftime("%Y/%m/%d %H:%M:%S", network_time()));
	
	print fmt("Cancyber Source Directory: %s", @DIR);
	
	# Load zeek format indicators
	load_indicators();
		
	# Update Zeek Rule Style Signatures and Source Code
	update_cancyber_source("../signatures/cancyber_sigs.sig", CCSOURCE);
	#update_cancyber_source("cancyber_expire.zeek", "cancyber_expire.zeek");
	#update_cancyber_source("cancyber_sigs.zeek", "cancyber_sigs.zeek");

	# Force output into stdout.log when using zeekctl
	flush_all();
}


event signature_match(state: signature_state, msg: string, data: string)
{
	local sig_id = state$sig_id;
	
	# Ensure this is a CanCyber signature
	if (strstr(sig_id,"cancyber") == 0) {
		return;
	}
		
	local src_addr: addr;
	local src_port: port;
	local dst_addr: addr;
	local dst_port: port;
	local di = NO_DIRECTION;


	if ( state$is_orig )
	{
		src_addr = state$conn$id$orig_h;
		src_port = state$conn$id$orig_p;
		dst_addr = state$conn$id$resp_h;
		dst_port = state$conn$id$resp_p;
	}
	else
	{
		src_addr = state$conn$id$resp_h;
		src_port = state$conn$id$resp_p;
		dst_addr = state$conn$id$orig_h;
		dst_port = state$conn$id$orig_p;
	}
	
	local hit = "ZEEK";
	if (state$conn?$uid) {
		hit += fmt("|uid:%s",state$conn$uid);
	}
	if (state$conn?$http && state$conn$http?$ts) {
		hit += fmt("|ts:%f",state$conn$http$ts);
	}
	
	hit += fmt("|orig_h:%s|orig_p:%s|resp_h:%s|resp_p:%s",src_addr,src_port,dst_addr,dst_port);
	local conn = state$conn;

	if (Site::is_local_addr(conn$id$orig_h) || Site::is_private_addr(conn$id$orig_h) ) {
		di = OUTBOUND;
	} else if (Site::is_local_addr(conn$id$resp_h) || Site::is_private_addr(conn$id$resp_h) ) {
		di = INBOUND;
	}


	if (di == OUTBOUND) {
		hit += "|d:OUTBOUND";
	} else if (di == INBOUND) {
		hit += "|d:INBOUND";
	}

	if (conn?$service) {
		hit += "|service:";
		local service = conn$service;
		local servicename: string = "";
		for ( ser in service ) {
			servicename += fmt("%s,",ser);
		}
		if (|servicename| > 0) {
			hit += cut_tail(servicename, 1);
		}
	}

	if (conn?$orig) {
		local orig = conn$orig;
		if (orig?$size) {
			hit += fmt("|orig:%s",orig$size);
		}
		if (orig?$num_pkts) {
			hit += fmt("|o_pkts:%s",orig$num_pkts);
		}
		if (orig?$num_bytes_ip) {
			hit += fmt("|o_bytes:%s",orig$num_bytes_ip);
		}
		if (orig?$state) {
			hit += fmt("|o_state:%s",orig$state);
		}
	}

	if (conn?$resp) {
		local resp = conn$resp;
		if (resp?$size) {
			hit += fmt("|resp:%s",resp$size);
		}
		if (resp?$num_pkts) {
			hit += fmt("|r_pkts:%s",resp$num_pkts);
		}
		if (resp?$num_bytes_ip) {
			hit += fmt("|r_bytes:%s",resp$num_bytes_ip);
		}
		if (resp?$state) {
			hit += fmt("|r_state:%s",resp$state);
		}
	}

	if (conn?$start_time) {
		hit += fmt("|start_time:%s",conn$start_time);
	}

	if (conn?$duration) {
		hit += fmt("|duration:%s",conn$duration);
	}

	if (conn?$http) {
		local http = conn$http;
		if (http?$host) {
			hit += fmt("|host:%s",http$host);
		}
		if (http?$uri) {
			hit += fmt("|uri:%s",http$uri);
		}
		if (http?$method) {
			hit += fmt("|method:%s",http$method);
		}
	}

	if (conn?$ssl) {
		local ssl = conn$ssl;
		if (ssl?$server_name) {
			hit += fmt("|sni:%s",ssl$server_name);
			if (ssl?$issuer) {
				hit += fmt("|issuer:%s",ssl$issuer);
			}
		}
	}


	if (conn?$smtp) {
		local smtp = conn$smtp;
		if (smtp?$from) {
			hit += fmt("|from:%s",smtp$from);
		}
		if (smtp?$subject) {
			hit += fmt("|subject:%s",smtp$subject);
		}
		if (smtp?$rcptto) {
			hit += fmt("|to:%s",smtp$rcptto);
		}
	}

	if (conn?$dns) {
		local dns = conn$dns;
		if (dns?$qtype_name) {
			hit += fmt("|q:%s",dns$qtype_name);
		}
		if (dns?$answers) {
			hit += fmt("|answers:%s",dns$answers);
		}
	}

	
	hit += "|sigid:" + sig_id + "|msg:" + msg;
	
	# This should always be true but check just in case
	if (|hit| < 1800) {
		# Trim the matched data down to fit the sql hit structure limit
		if ( (|data| + |hit|) > 2000 )
			data = fmt("%s...", sub_bytes(data, 0, 2000-|hit|));

		hit += "|data:" + data;
	}
	
	register_hit(hit);
	#print "Signature Hit: " + hit;
}

event zeek_init()
{
	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER) {
		startup_intel();
		event do_reload_signatures();
	} else if ( !Cluster::is_enabled() ) {
		startup_intel();
		schedule signature_refresh_period {do_reload_signatures()};
	}
}

event file_new(f: fa_file)
{
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
}


#!/usr/bin/env python3

import sys
from datetime import datetime
# using RawPcap* classes to avoid unnecessary processing of packets
from scapy.utils import RawPcapReader, RawPcapWriter

reference = sys.argv[1]
modify = sys.argv[2]
modify_out = sys.argv[3]

def time_range(pcap):
	'''Finds the first and last packet times in the pcap.
	Also returns the total packet count.'''
	start_time = 1e100
	end_time = 0
	count = 0
	for pkt, meta in pcap:
		count += 1
		if meta is None: continue
		if meta.sec < start_time:
			start_time = meta.sec
		elif meta.sec > end_time:
			end_time = meta.sec
	return (start_time, end_time, count)

def should_normalize(ref_range, mod_range):
	'''Determines whether or not the modify pcap
	times should be expanded or shrunk to match the reference.'''

	# If the reference and modify pcap dates are
	# similar lengths (e.g. 23 hours and 24 hours)
	# there is no need to normalize timestamps.
	# Actual cutoff is +/- 10% (1.1 and 0.9)
	return not (1/1.1) < ref_range / mod_range < (1/0.9)

def format_utc(sec):
	return datetime.utcfromtimestamp(sec).strftime('%Y-%m-%d %H:%M:%S')

with RawPcapReader(reference) as ref:
	ref_start, ref_end, ref_count = time_range(ref)
	print('ref start={start}, end={end}'.format(
		start=format_utc(ref_start),
		end=format_utc(ref_end)
		))

with RawPcapReader(modify) as mod_in:
	mod_start, mod_end, mod_count = time_range(mod_in)
	print('mod start={start}, end={end}'.format(
		start=format_utc(mod_start),
		end=format_utc(mod_end)
		))

# ref_start=1516826211
# ref_end=1516912610
# mod_start=1517336042
# mod_end=1517422440
# mod_count=4_156_081

# number of packets to process before output
status_period = mod_count // 10

with RawPcapReader(modify) as mod_in, \
	RawPcapWriter(modify_out, 
		linktype=mod_in.linktype, 
		endianness=mod_in.endian, 
		nano=mod_in.nano) as mod_out:

	count = 0
	# all packets should end up between ref_start and ref_end
	ref_range = ref_end - ref_start
	mod_range = mod_end - mod_start

	# since we're using the _write_packet internal function
	# must call _write_header manually, which has a required
	# parameter that isn't used
	mod_out._write_header(None)

	if should_normalize(ref_range, mod_range):
		print('Normalizing: pcaps time ranges are more than 10%')
		for pkt, meta in mod_in:
			if meta is not None:
				sec = meta.sec
				# normalize the value
				norm = (sec - mod_start) / mod_range
				# now denormalize in the new reference range
				sec = int(ref_range * norm) + ref_start

				# print a status periodically
				count += 1
				if count % status_period == 0:
					print('in={before}, out={after}'.format(
						before=format_utc(meta.sec),
						after=format_utc(sec)
						))

			# must use internal _write_packet in order to pass in custom time
			mod_out._write_packet(pkt, 
				sec=sec, 
				usec=meta.usec, 
				caplen=meta.caplen,
				wirelen=meta.wirelen
				)

	else:
		print('Not normalizing: pcaps time ranges are within 10%')
		# if reference is after modify then we just end up adding diff
		# (subracting a negative offset)
		diff = mod_start - ref_start
		for pkt, meta in mod_in:
			if meta is not None:
				sec = meta.sec - diff

				# print a status periodically
				count += 1
				if count % status_period == 0:
					print('in={before}, out={after}'.format(
						before=format_utc(meta.sec),
						after=format_utc(sec)
						))

			# must use internal _write_packet in order to pass in custom time
			mod_out._write_packet(pkt, 
				sec=sec, 
				usec=meta.usec, 
				caplen=meta.caplen,
				wirelen=meta.wirelen
				)



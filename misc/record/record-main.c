/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2018, 2019 embedded brains GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <rtems/recorddata.h>
#include <rtems/recordclient.h>

#include <sys/queue.h>
#include <sys/socket.h>

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h> 
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "tree.h"

#define THRESHOLD_IN_NS 500000000
#define CTF_MAGIC 0xC1FC1FC1

static const struct option longopts[] = {
  { "help", 0, NULL, 'h' },
  { "host", 1, NULL, 'H' },
  { "port", 1, NULL, 'p' },
  { "items", 1, NULL, 'i' },
  { "input", 1, NULL, 'f' },
  { NULL, 0, NULL, 0 }
};

typedef struct client_item {
  union {
    SLIST_ENTRY( client_item ) free_node;
    RB_ENTRY( client_item )    active_node;
  };
  uint64_t                     ns;
  uint32_t                     cpu;
  rtems_record_event           event;
  uint64_t                     data;
  uint64_t                     counter;
} client_item;

typedef struct ctf_packet_header {
  uint32_t                     ctf_magic;
  uint8_t                      uuid[ 16 ];
  uint32_t                     stream_id;
  uint64_t                     stream_instance_id;
} __attribute__((__packed__)) ctf_packet_header;

typedef struct ctf_packet_context {
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
  uint64_t content_size;
	uint64_t packet_size;
  uint64_t packet_seq_num;
	unsigned long events_discarded;
	uint32_t cpu_id;
} __attribute__((__packed__)) ctf_packet_context;

typedef struct event_header_extended {
  uint8_t  id;
  uint32_t event_id;
  uint64_t ns;
} __attribute__((__packed__)) event_header_extended;

typedef struct switch_event{
  uint8_t                      prev_comm[16];
  int32_t                      prev_tid;
  int32_t                      prev_prio;
  int64_t                      prev_state;
  uint8_t                      next_comm[16];
  int32_t                      next_tid;
  int32_t                      next_prio;
} __attribute__((__packed__)) switch_event;

typedef struct client_context {
  uint64_t                       ns_threshold;
  uint64_t                       last_ns;
  uint32_t                       last_cpu;
  bool                           flush;
  bool                           only_one_cpu;
  uint64_t                       counter;
  SLIST_HEAD( , client_item )    free_items;
  RB_HEAD( active, client_item ) active_items;
  FILE               *event_streams[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];
  uint64_t            timestamp_begin[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];
	uint64_t            timestamp_end[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];
  uint64_t            content_size[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];
  uint64_t            packet_size[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];
  switch_event        sched_switch[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ][3];
  uint64_t            ns[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];
} client_context;

static const uint8_t uuid[] = { 0x6a, 0x77, 0x15, 0xd0, 0xb5, 0x02, 0x4c, 0x65,
    0x86, 0x78, 0x67, 0x77, 0xac, 0x7f, 0x75, 0x5a };

static inline int item_cmp( const void *pa, const void *pb )
{
  const client_item *a;
  const client_item *b;

  a = (const client_item *) pa;
  b = (const client_item *) pb;

  if ( a->ns < b->ns ) {
    return -1;
  } else if ( a->ns > b->ns ) {
    return 1;
  } else if ( a->counter < b->counter ) {
    return -1;
  } else {
    /* The counter are never equal */
    return 1;
  }
}

RB_GENERATE_INTERNAL( active, client_item, active_node, item_cmp, static inline )

static void usage( char **argv )
{
  printf(
    "%s [--host=HOST] [--port=PORT] [--items=ITEMS] [--input=INPUT]\n"
    "\n"
    "Mandatory arguments to long options are mandatory for short options too.\n"
    "  -h,      --help             print this help text\n"
    "  -H,      --host=HOST        the host IPv4 address of the record server\n"
    "  -p,      --port=PORT        the TCP port of the record server\n"
    "  -i,      --items=ITEMS      the maximum count of active record items\n"
    "  -f,      --input=INPUT      the file input\n",
    argv[ 0 ]
  );
}

static int connect_client( const char *host, uint16_t port, 
const char *input_file, bool input_file_flag )
{
  struct sockaddr_in in_addr;
  int fd;
  int rv;

  fd = ( input_file_flag ) ? open( input_file, O_RDONLY ) : 
  socket( PF_INET, SOCK_STREAM, 0 ); 
  assert( fd >= 0 );   
  

  memset( &in_addr, 0, sizeof( in_addr ) );
  in_addr.sin_family = AF_INET;
  in_addr.sin_port = htons( port );
  in_addr.sin_addr.s_addr = inet_addr( host );
  if( !input_file_flag ){
    rv = connect( fd, (struct sockaddr *) &in_addr, sizeof( in_addr ) );
    assert( rv == 0 );
  }

  return fd;
}

static void print_item( client_context *cctx, const client_item *item )
{

  if( cctx->timestamp_begin[ item->cpu ] == 0 ) 
      cctx->timestamp_begin[ item->cpu ] = item->ns;
  cctx->timestamp_end[ item->cpu ] = item->ns;

  if( item->event == 216 ){

    // prev_* values of RTEMS_RECORD_THREAD_SWITCH_OUT
    char item_data_str[ 256 ];
    snprintf( item_data_str, sizeof( item_data_str ), "%08"PRIx64, item->data );
    memcpy( cctx->sched_switch[ item->cpu ][ 0 ].prev_comm, item_data_str, 
    sizeof( cctx->sched_switch[ item->cpu  ][ 0 ].prev_comm ) );
    cctx->sched_switch[ item->cpu ][ 0 ].prev_tid = item->data;
    cctx->sched_switch[ item->cpu ][ 0 ].prev_prio = 0;
    cctx->sched_switch[ item->cpu ][ 0 ].prev_state = 0;

    cctx->ns[ item->cpu ] = item->ns;


  }else if( item->event == 209 ){

    // next_* values of RTEMS_RECORD_THREAD_SWITCH_OUT
    char item_data_str[ 256 ];
    snprintf( item_data_str, sizeof( item_data_str ), "%08"PRIx64, item->data );
    memcpy( cctx->sched_switch[ item->cpu ][ 0 ].next_comm, item_data_str, 
    sizeof( cctx->sched_switch[ item->cpu  ][ 0 ].next_comm ) );
    cctx->sched_switch[ item->cpu ][ 0 ].next_tid = item->data;
    cctx->sched_switch[ item->cpu ][ 0 ].next_prio = 0;

    // prev_* values of RTEMS_RECORD_THREAD_STACK_CURRENT
    memcpy( cctx->sched_switch[ item->cpu ][ 1 ].prev_comm, item_data_str, 
    sizeof( cctx->sched_switch[ item->cpu  ][ 1 ].prev_comm ) );
    cctx->sched_switch[ item->cpu ][ 1 ].prev_tid = item->data;
    cctx->sched_switch[ item->cpu ][ 1 ].prev_prio = 0;
    cctx->sched_switch[ item->cpu ][ 1 ].prev_state = 0;

  }else if( item->event == 215 ){
    
    // next_* values of RTEMS_RECORD_THREAD_STACK_CURRENT
    char item_data_str[ 256 ];
    snprintf( item_data_str, sizeof( item_data_str ), "%08"PRIx64, item->data );
    memcpy( cctx->sched_switch[ item->cpu ][ 1 ].next_comm, item_data_str, 
    sizeof( cctx->sched_switch[ item->cpu  ][ 1 ].next_comm ) );
    cctx->sched_switch[ item->cpu ][ 1 ].next_tid = item->data;
    cctx->sched_switch[ item->cpu ][ 1 ].next_prio = 0;

    // prev_* and next_* values of RTEMS_RECORD_THREAD_SWITCH_IN

    memcpy( cctx->sched_switch[ item->cpu ][ 2 ].prev_comm, item_data_str, 
    sizeof( cctx->sched_switch[ item->cpu  ][ 2 ].prev_comm ) );
    cctx->sched_switch[ item->cpu ][ 2 ].prev_tid = item->data;
    cctx->sched_switch[ item->cpu ][ 2 ].prev_prio = 0;
    cctx->sched_switch[ item->cpu ][ 2 ].prev_state = 0;

    memcpy( cctx->sched_switch[ item->cpu ][ 2 ].next_comm, 
    cctx->sched_switch[ item->cpu ][ 0 ].prev_comm, 
    sizeof( cctx->sched_switch[ item->cpu  ][ 2 ].next_comm ) );
    cctx->sched_switch[ item->cpu ][ 2 ].next_tid = cctx->sched_switch[ item->cpu ][ 0 ].prev_tid;
    cctx->sched_switch[ item->cpu ][ 2 ].next_prio = 0;

    

    if( cctx->ns[ item->cpu ] == item->ns ){

      size_t i;

      for( i = 0; i < 3; i++){
        event_header_extended event_header_extended;
        FILE **f = cctx->event_streams;

        event_header_extended.id = ( uint8_t ) 31; //points to extended struct of metadata
        event_header_extended.event_id = ( uint32_t ) item->cpu; // points to event_id of metadata
        event_header_extended.ns = ( uint64_t ) item->ns; // timestamp value

        cctx->content_size[ item->cpu ] += sizeof( event_header_extended ) * 8; 
        cctx->packet_size[ item->cpu ] += sizeof( event_header_extended ) * 8;

        cctx->content_size[ item->cpu ] += sizeof( cctx->sched_switch[ item->cpu ][i] ) * 8; 
        cctx->packet_size[ item->cpu] += sizeof( cctx->sched_switch[ item->cpu ][i] ) * 8;
      
        fwrite( &event_header_extended, sizeof( event_header_extended ), 1, f[ item->cpu ] );
        fwrite( &cctx->sched_switch[ item->cpu ][i], sizeof( cctx->sched_switch[ item->cpu ][i] ), 
        1, f[ item->cpu ] );
      
      }

    }
  
  }

}

static void flush_items( client_context *cctx )
{
  uint64_t ns;
  uint64_t ns_threshold;
  client_item *x;
  client_item *y;

  ns = cctx->last_ns;
  ns_threshold = cctx->ns_threshold;

  if ( ns >= ns_threshold ) {
    cctx->ns_threshold = ( ( ns + THRESHOLD_IN_NS - 1 ) / THRESHOLD_IN_NS )
      * THRESHOLD_IN_NS;
    ns_threshold -= THRESHOLD_IN_NS;
  }

  if ( SLIST_EMPTY( &cctx->free_items ) ) {
    uint64_t somewhere_in_the_middle;

    somewhere_in_the_middle = RB_ROOT( &cctx->active_items )->ns;

    if ( ns_threshold < somewhere_in_the_middle ) {
      ns_threshold = somewhere_in_the_middle;
    }
  }

  RB_FOREACH_SAFE( x, active, &cctx->active_items, y ) {
    if ( x->ns > ns_threshold ) {
      break;
    }

    RB_REMOVE( active, &cctx->active_items, x );
    SLIST_INSERT_HEAD( &cctx->free_items, x, free_node );
    print_item( cctx, x);

  }
}

static rtems_record_client_status handler(
  uint32_t            seconds,
  uint32_t            nanoseconds,
  uint32_t            cpu,
  rtems_record_event  event,
  uint64_t            data,
  void               *arg
)
{
  client_context *cctx;
  client_item *item;
  uint64_t ns;
  bool flush;

  cctx = arg;

  if ( cpu != 0 ) {
    cctx->only_one_cpu = false;
  }

  ns = ( (uint64_t) seconds * 1000000000 ) + nanoseconds;

  if ( cctx->only_one_cpu ) {
    flush = ( ns >= cctx->ns_threshold );
  } else {
    if ( cpu != cctx->last_cpu ) {
      cctx->last_cpu = cpu;

      if ( cpu == 0 ) {
        flush = ( cctx->flush && cctx->last_ns >= cctx->ns_threshold );
        cctx->flush = true;
      } else {
        flush = false;
        cctx->flush = ( cctx->flush && cctx->last_ns >= cctx->ns_threshold );
      }
    } else {
      flush = false;
    }
  }

  if (
    ns != 0
      && event != RTEMS_RECORD_UPTIME_LOW
      && event != RTEMS_RECORD_UPTIME_HIGH
  ) {
    uint64_t counter;

    cctx->last_ns = ns;

    item = SLIST_FIRST( &cctx->free_items );
    SLIST_REMOVE_HEAD( &cctx->free_items, free_node );
    item->ns = ns;
    item->cpu = cpu;
    item->event = event;
    item->data = data;

    counter = cctx->counter;
    cctx->counter = counter + 1;
    item->counter = counter;

    RB_INSERT( active, &cctx->active_items, item );
  }

  if ( flush || SLIST_EMPTY( &cctx->free_items ) ) {
    flush_items( cctx );
  }

  return RTEMS_RECORD_CLIENT_SUCCESS;
}

int main( int argc, char **argv )
{
  rtems_record_client_context ctx;
  client_context cctx;
  client_item *items;
  ctf_packet_header ctf_packet_header;
  ctf_packet_context ctf_packet_context;
  const char *host;
  uint16_t port;
  const char *input_file;
  bool input_file_flag = false;
  bool input_TCP_host = false;
  bool input_TCP_port = false;
  int fd;
  int rv;
  int opt;
  int longindex;
  size_t n;
  size_t i;

  host = "127.0.0.1";
  port = 1234;
  input_file = "raw_data";
  n = RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT * 1024 * 1024;

  while (
    ( opt = getopt_long( argc, argv, "hH:p:i:f", &longopts[0], &longindex ) )
      != -1
  ) {
    switch ( opt ) {
      case 'h':
        usage( argv );
        exit( EXIT_SUCCESS );
        break;
      case 'H':
        host = optarg;
        input_TCP_host = true;
        break;
      case 'p':
        port = (uint16_t) strtoul( optarg, NULL, 10 );
        input_TCP_port = true;
        break;
      case 'i':
        n = (size_t) strtoul( optarg, NULL, 10 );
        break;
      case 'f':
        input_file = optarg;
        assert( input_file != NULL );
        input_file_flag = true;
        break;
      default:
        exit( EXIT_FAILURE );
        break;
    }
  }

  if( input_file_flag && ( input_TCP_host || input_TCP_port ) ){
    printf( "There should be one input medium\n" );
    exit( EXIT_SUCCESS );
  }

  memset( &cctx, 0, sizeof( cctx ) );
  cctx.only_one_cpu = true;
  cctx.ns_threshold = 2 * THRESHOLD_IN_NS;
  SLIST_INIT( &cctx.free_items );
  RB_INIT( &cctx.active_items );

  memcpy( ctf_packet_header.uuid, uuid, sizeof( ctf_packet_header.uuid ) );

  FILE *event_streams[ RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ];

  for( i = 0; i < RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ; i++ ) {
    char filename[ 256 ] = "event_";
    char file_index[ 256 ];
    snprintf( file_index, sizeof( file_index ), "%ld", i );
    strcat( filename, file_index );

    event_streams[ i ] = fopen( filename , "wb" );

    ctf_packet_header.ctf_magic = CTF_MAGIC;
    ctf_packet_header.stream_id = ( uint32_t ) 0;
    ctf_packet_header.stream_instance_id = ( uint64_t ) i;

    // Add dummy data at the begining of file so that later only this part
    // can be overwritten
    ctf_packet_context.timestamp_begin = ( uint64_t ) 0;
    ctf_packet_context.timestamp_end = ( uint64_t ) 0;
    ctf_packet_context.content_size = ( uint64_t ) 0;
    ctf_packet_context.packet_size = ( uint64_t ) 0;
    ctf_packet_context.cpu_id = ( uint32_t ) i;
    ctf_packet_context.packet_seq_num = ( uint64_t ) 0;
    ctf_packet_context.events_discarded = ( uint64_t ) 0;

    // CTF magic, uuid, stream_id = 0 and cpu_id of each file. It is needed 
    // to be added the very begining of each stream file
    fwrite( &ctf_packet_header, sizeof( ctf_packet_header ), 1, event_streams[ i ] );

    //wrting packet context just after packet header
    fwrite( &ctf_packet_context, sizeof( ctf_packet_context ), 1, event_streams[ i ] );

    //initializing equal timestamp values per CPU 
    cctx.timestamp_begin[ i ] = ( uint64_t ) 0;
    cctx.timestamp_end[ i ] = ( uint64_t ) 0;
    
    cctx.content_size[ i ] = ( uint64_t ) 0;
    cctx.packet_size[ i ] = ( uint64_t ) 0;

    assert( event_streams[ i ] != NULL );
    cctx.event_streams[ i ] = event_streams[ i ];
  }

  items = calloc( n, sizeof( *items ) );
  assert( items != NULL );

  for ( i = 0; i < n; ++i ) {
    SLIST_INSERT_HEAD( &cctx.free_items, &items[ i ], free_node );
  }

  fd = connect_client( host, port, input_file, input_file_flag );
  rtems_record_client_init( &ctx, handler, &cctx );

  while ( true ) {
    int buf[ 8192 ];
    ssize_t n;

      n = ( input_file_flag ) ? read( fd, buf, sizeof( buf ) ) : 
      recv( fd, buf, sizeof( buf ), 0 );
      if ( n > 0 ) {
        rtems_record_client_run( &ctx, buf, (size_t) n );
      } else {
        break;
      }

  }

  // It will overwrite the packet.header and packet.context only at the 
  // beginning and won't overwirte the rest data.
  for( i = 0; i < RTEMS_RECORD_CLIENT_MAXIMUM_CPU_COUNT ; i++ ) {
    fseek( event_streams[ i ], 0, SEEK_SET );

    ctf_packet_header.ctf_magic = CTF_MAGIC;
    ctf_packet_header.stream_id = ( uint32_t ) 0;
    ctf_packet_header.stream_instance_id = ( uint64_t ) i;

    // Replacing the dummy data with actual values.
    ctf_packet_context.timestamp_begin = ( uint64_t ) cctx.timestamp_begin[ i ];
    ctf_packet_context.timestamp_end = ( uint64_t ) cctx.timestamp_end[ i ];
    
    //content_size and packet_size includes all headers and event sizes in bits
    //There is no padding in native binary stream files so both should be equal
    ctf_packet_context.content_size = ( uint64_t ) cctx.content_size[ i ] + 
    ( sizeof( ctf_packet_header ) + sizeof( ctf_packet_context ) ) * 8;
    ctf_packet_context.packet_size = ( uint64_t ) cctx.packet_size[ i ] +
    ( sizeof( ctf_packet_header ) + sizeof( ctf_packet_context ) ) * 8;

    ctf_packet_context.packet_seq_num = ( uint64_t ) 0;
    ctf_packet_context.events_discarded = ( uint64_t ) 0;

    ctf_packet_context.cpu_id = ( uint32_t ) i;

    // CTF magic, uuid, stream_id = 0 and cpu_id of each file. It is needed 
    // to be added the very begining of each stream file
    fwrite( &ctf_packet_header, sizeof( ctf_packet_header ), 1, event_streams[ i ] );

    //wrting packet context just after packet header
    fwrite( &ctf_packet_context, sizeof( ctf_packet_context ), 1, event_streams[ i ] );

    fclose( event_streams[ i ] );

  }

  rv = close( fd );
  assert( rv == 0 );

  return 0;
}

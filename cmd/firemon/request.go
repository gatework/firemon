package main

import (
	"context"
	"errors"
	"io"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
)

func requestCommand(ctx context.Context, command string, args []string, out io.Writer) error {
	fs := flags(command, out)
	root := fs.String("store", "", "snapshot directory")
	file := fs.String("file", "", "request JSON")
	src := fs.String("src", "", "source IPs, networks or ranges")
	dst := fs.String("dst", "", "destination IPs, networks or ranges")
	service := fs.String("service", "", "ports, tcp/ports or udp/ports; omitted queries all services")
	at := fs.String("at", "", "query instant (RFC3339; default now)")
	start := fs.String("start", "", "interval start (RFC3339, inclusive)")
	end := fs.String("end", "", "interval end (RFC3339, exclusive)")
	topologyFile := fs.String("topology", "", "version-1 topology JSON")
	clocksFile := fs.String("clocks", "", "device clock evidence JSON for finite policy design")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" {
		return usage(errors.New("store is required"))
	}
	var request operations.BatchRequest
	if *file != "" {
		if *src != "" || *dst != "" || *service != "" || *at != "" || *start != "" || *end != "" {
			return usage(errors.New("file cannot be combined with traffic or time flags"))
		}
		input, finish, err := openInput(ctx, *file)
		if err != nil {
			return err
		}
		var decodeErr error
		request, decodeErr = operations.DecodeBatchRequest(ctx, input)
		if err := errors.Join(usage(decodeErr), finish()); err != nil {
			return err
		}
	} else {
		if *src == "" || *dst == "" {
			return usage(errors.New("src and dst, or file, are required"))
		}
		if (*at != "" && (*start != "" || *end != "")) || (*start == "") != (*end == "") {
			return usage(errors.New("choose at or both start and end"))
		}
		a := operations.AccessRequest{Src: *src, Dst: *dst, Service: *service}
		if *at != "" {
			instant, err := time.Parse(time.RFC3339, *at)
			if err != nil {
				return usage(err)
			}
			a.At = instant
		}
		if *start != "" {
			first, err := time.Parse(time.RFC3339, *start)
			if err != nil {
				return usage(err)
			}
			last, err := time.Parse(time.RFC3339, *end)
			if err != nil || !first.Before(last) {
				return usage(errors.New("end must be an RFC3339 instant after start"))
			}
			a.Window = &fm.TimeWindow{Start: first, End: last}
		}
		request = operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{a}}
	}
	if *topologyFile != "" {
		f, finish, err := openInput(ctx, *topologyFile)
		if err != nil {
			return err
		}
		top, decodeErr := operations.DecodeTopology(ctx, f)
		closeErr := finish()
		if err := errors.Join(usage(decodeErr), closeErr); err != nil {
			return err
		}
		request.Topology = &top
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return snapshotArgumentError(err)
	}
	var result operations.BatchReport
	if command == "request-plan" {
		options := operations.BatchDesignerOptions{Store: store}
		if *clocksFile != "" {
			if err := readJSON(ctx, *clocksFile, &options.Clocks); err != nil {
				return err
			}
		}
		designer, initErr := operations.NewBatchDesigner(options)
		if initErr != nil {
			return initErr
		}
		result, err = designer.Design(ctx, request)
	} else {
		if *clocksFile != "" {
			return usage(errors.New("clocks applies to request-plan"))
		}
		searcher, initErr := operations.NewSearcher(operations.SearcherOptions{Store: store})
		if initErr != nil {
			return initErr
		}
		result, err = searcher.Query(ctx, request)
	}
	if err != nil {
		return err
	}
	return output(out, result.Document())
}

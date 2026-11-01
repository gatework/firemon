package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
)

func requestCommand(ctx context.Context, command string, args []string, out io.Writer) error {
	fs := flags(command)
	root := fs.String("store", "", "snapshot directory")
	file := fs.String("file", "", "version-1 request JSON")
	topologyFile := fs.String("topology", "", "version-1 topology JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *file == "" {
		return errors.New("store and file are required")
	}
	input, err := os.Open(*file)
	if err != nil {
		return err
	}
	request, decodeErr := operations.DecodeBatchRequest(input)
	closeErr := input.Close()
	if err = errors.Join(decodeErr, closeErr); err != nil {
		return err
	}
	if *topologyFile != "" {
		f, err := os.Open(*topologyFile)
		if err != nil {
			return err
		}
		top, decodeErr := operations.DecodeTopology(f)
		closeErr := f.Close()
		if err = errors.Join(decodeErr, closeErr); err != nil {
			return err
		}
		request.Topology = &top
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return err
	}
	designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	if err != nil {
		return err
	}
	var result operations.BatchReport
	if command == "request-plan" {
		result, err = designer.Design(ctx, request)
	} else {
		result, err = designer.Query(ctx, request)
	}
	if err != nil {
		return err
	}
	return output(out, result.Document())
}

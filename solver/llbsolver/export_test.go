package llbsolver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/buildkit/exporter"
	"github.com/moby/buildkit/solver"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

type testExporter struct {
	exporter.ExporterInstance // unused methods panic
	name                      string
	export                    func(context.Context) (exporter.FinalizeFunc, error)
}

func (e *testExporter) Name() string { return e.name }

func (e *testExporter) Export(ctx context.Context, _ *exporter.Source, _ exporter.ExportBuildInfo) (map[string]string, exporter.FinalizeFunc, exporter.DescriptorReference, error) {
	f, err := e.export(ctx)
	return map[string]string{e.name: "done"}, f, nil, err
}

func newTestJob(t *testing.T) *solver.Job {
	j, err := solver.NewSolver(solver.SolverOpt{}).NewJob(t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, j.Discard()) })
	return j
}

// TestRunExportersFinalizeDoesNotWaitForOtherExporters checks that an
// exporter's finalize (the registry push) starts as soon as its own Export
// returns, while another exporter is still exporting, and that cache export
// starts only after every Export has returned.
func TestRunExportersFinalizeDoesNotWaitForOtherExporters(t *testing.T) {
	finalizeStarted := make(chan struct{})
	var slowExported atomic.Bool
	push := &testExporter{name: "push", export: func(context.Context) (exporter.FinalizeFunc, error) {
		return func(context.Context) error {
			close(finalizeStarted)
			return nil
		}, nil
	}}
	// slow stands in for e.g. the tarball stream of --load.
	slow := &testExporter{name: "slow", export: func(ctx context.Context) (exporter.FinalizeFunc, error) {
		defer slowExported.Store(true)
		select {
		case <-finalizeStarted:
			return nil, nil
		case <-time.After(10 * time.Second):
			return nil, errors.New("finalize of the other exporter did not start while this exporter was exporting")
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}}

	var cacheExportRan bool
	resp, _, err := (&Solver{}).runExporters(t.Context(), "ref", []exporter.ExporterInstance{push, slow}, nil, newTestJob(t), nil, &exporter.Source{}, func(context.Context) error {
		if !slowExported.Load() {
			return errors.New("cache export started before every exporter returned")
		}
		cacheExportRan = true
		return nil
	})
	require.NoError(t, err)
	require.True(t, cacheExportRan)
	require.Equal(t, map[string]string{"push": "done", "slow": "done"}, resp)
}

// TestRunExportersErrorCancelsFinalize checks that a failing exporter cancels
// the finalize of another exporter that already started.
func TestRunExportersErrorCancelsFinalize(t *testing.T) {
	finalizeStarted := make(chan struct{})
	push := &testExporter{name: "push", export: func(context.Context) (exporter.FinalizeFunc, error) {
		return func(ctx context.Context) error {
			close(finalizeStarted)
			<-ctx.Done()
			return context.Cause(ctx)
		}, nil
	}}
	failing := &testExporter{name: "failing", export: func(context.Context) (exporter.FinalizeFunc, error) {
		<-finalizeStarted
		return nil, errors.New("export failed")
	}}
	var cacheExportRan atomic.Bool
	_, _, err := (&Solver{}).runExporters(t.Context(), "ref", []exporter.ExporterInstance{push, failing}, nil, newTestJob(t), nil, &exporter.Source{}, func(context.Context) error {
		cacheExportRan.Store(true)
		return nil
	})
	require.ErrorContains(t, err, "export failed")
	require.False(t, cacheExportRan.Load())
}

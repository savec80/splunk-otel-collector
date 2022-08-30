// Copyright Splunk, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package discoveryreceiver

import (
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/observer"
	"go.opentelemetry.io/collector/config"
	"go.uber.org/zap"

	"github.com/signalfx/splunk-otel-collector/internal/receiver/discoveryreceiver/statussources"
)

// correlation is a grouping of an endpoint, an
// associated receiver, if any, and the observing observer.
// It's used to unify log record content from evaluated
// status sources such that no source lacks information
// that would be available to others.
type correlation struct {
	lastEndpointState endpointState
	lastUpdated       time.Time
	endpoint          observer.Endpoint
	receiverID        config.ComponentID
	observerID        config.ComponentID
}

// correlationStore is a collection of mappings used
// as an instantaneous record of
// 1. endpoints to their associated receivers/correlations
// 2. receivers to their endpoint-agnostic Attrs used as a message
// passing mechanism (currently just for embedded config values)
type correlationStore struct {
	logger        *zap.Logger
	correlations  *sync.Map
	endpointLocks *keyLock
	receiverAttrs *sync.Map
	receiverLocks *keyLock
	sentinel      chan struct{}
	ttl           time.Duration
}

func newCorrelationStore(logger *zap.Logger, ttl time.Duration) *correlationStore {
	return &correlationStore{
		logger:        logger,
		correlations:  &sync.Map{},
		endpointLocks: newKeyLock(),
		receiverAttrs: &sync.Map{},
		receiverLocks: newKeyLock(),
		ttl:           ttl,
		sentinel:      make(chan struct{}, 1),
	}
}

func (cs *correlationStore) start() {
	go func() {
		timer := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-timer.C:
				cs.correlations.Range(func(eID, rMap any) bool {
					endpointID := eID.(observer.EndpointID)
					defer cs.endpointLocks.Lock(endpointID)()
					receiverMap := rMap.(*sync.Map)
					if c, ok := receiverMap.Load(statussources.NoType); ok {
						corr := c.(*correlation)
						if corr.lastEndpointState == removedState &&
							time.Since(corr.lastUpdated) > cs.ttl {
							cs.correlations.Delete(endpointID)
						}
					}
					return true
				})
			case <-cs.sentinel:
				timer.Stop()
				return
			}
		}
	}()
}

func (cs *correlationStore) stop() {
	cs.sentinel <- struct{}{}
}

func (cs *correlationStore) Upsert(endpoint observer.Endpoint, state endpointState, observerID config.ComponentID) {
	defer cs.endpointLocks.Lock(endpoint.ID)()
	rStore, ok := cs.correlations.LoadOrStore(endpoint.ID,
		func() *sync.Map {
			receiverMap := &sync.Map{}
			receiverMap.Store(statussources.NoType, &correlation{
				lastEndpointState: state,
				lastUpdated:       time.Now(),
				endpoint:          endpoint,
				observerID:        observerID,
			})
			return receiverMap
		}())
	if !ok {
		return
	}
	rStore.(*sync.Map).Range(func(_, c any) bool {
		corr := c.(*correlation)
		corr.lastEndpointState = state
		corr.lastUpdated = time.Now()
		corr.endpoint = endpoint
		return true
	})
}

func (cs *correlationStore) correlationForReceiver(receiverID config.ComponentID, endpointID observer.EndpointID) correlation {
	defer cs.endpointLocks.Lock(endpointID)()
	ec, _ := cs.correlations.LoadOrStore(endpointID,
		func() *sync.Map {
			receiverStore := &sync.Map{}
			receiverStore.Store(statussources.NoType, &correlation{})
			return receiverStore
		}())
	receiverStore := ec.(*sync.Map)
	var corr *correlation
	if c, ok := receiverStore.Load(receiverID); ok {
		corr = c.(*correlation)
	} else {
		var noTypeCorrelation *correlation
		if ntc, loaded := receiverStore.Load(statussources.NoType); !loaded {
			// this should never happen since we would have created it just above w/ an endpoint lock
			cs.logger.Warn("noType endpoint correlation has been unexpectedly removed. Resetting w/ zero value")
			noTypeCorrelation = &correlation{}
			receiverStore.Store(statussources.NoType, noTypeCorrelation)
		} else {
			noTypeCorrelation = ntc.(*correlation)
		}
		cp := *noTypeCorrelation
		corr = &cp
		corr.receiverID = receiverID
		receiverStore.Store(receiverID, corr)
	}
	return *corr
}

func (cs *correlationStore) Attrs(receiverID config.ComponentID) map[string]string {
	defer cs.receiverLocks.Lock(receiverID)()
	rInfo, _ := cs.receiverAttrs.LoadOrStore(receiverID, map[string]string{})
	receiverInfo := rInfo.(map[string]string)
	cp := map[string]string{}
	for k, v := range receiverInfo {
		cp[k] = v
	}
	return cp
}

func (cs *correlationStore) UpdateAttrs(receiverID config.ComponentID, attrs map[string]string) map[string]string {
	defer cs.receiverLocks.Lock(receiverID)()
	rAttrs, _ := cs.receiverAttrs.LoadOrStore(receiverID, map[string]string{})
	receiverAttrs := rAttrs.(map[string]string)
	for k, v := range attrs {
		receiverAttrs[k] = v
	}
	cp := map[string]string{}
	for k, v := range receiverAttrs {
		cp[k] = v
	}
	cs.receiverAttrs.Store(receiverID, receiverAttrs)
	return cp
}

type keyLock struct {
	locks *sync.Map
}

func newKeyLock() *keyLock {
	return &keyLock{locks: &sync.Map{}}
}

func (kl *keyLock) Lock(key any) (unlock func()) {
	mtx, _ := kl.locks.LoadOrStore(key, &sync.Mutex{})
	mutex := mtx.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

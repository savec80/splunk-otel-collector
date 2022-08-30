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
	"fmt"
	"regexp"
	"sync"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/observer"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/signalfx/splunk-otel-collector/internal/receiver/discoveryreceiver/statussources"
)

var (
	observerIDAttr = "discovery.observer.id"
)

type evaluator struct {
	logger       *zap.Logger
	config       *Config
	pLogs        chan plog.Logs
	correlations *correlationStore
	// if match.FirstOnly this sync.Map(map[string]struct{}) keeps track of
	// if we've already emitted a record for the statement.
	alreadyLogged *sync.Map
	exprEnv       func(pattern string) expr.Option
}

// correlateResourceAttributes will copy all `from` attributes to `to` in addition to
// updating embedded base64 config content, if any, to include the correlated observer ID
func (e *evaluator) correlateResourceAttributes(from, to pcommon.Map, corr correlation) {
	receiverType := "unknown"
	receiverName := "unknown"
	if rType, ok := from.Get(statussources.ReceiverTypeAttr); ok {
		receiverType = rType.StringVal()
	}
	if rName, ok := from.Get(statussources.ReceiverNameAttr); ok {
		receiverName = rName.StringVal()
	}

	var receiverAttrs map[string]string
	temporaryReceiverConfigAttr := false
	receiverAttrs = e.correlations.Attrs(corr.receiverID)
	to.InsertString(observerIDAttr, corr.observerID.String())
	if e.config.EmbedReceiverConfig {
		if _, ok := from.Get(receiverConfigAttr); !ok {
			// statements don't inherit embedded configs in their resource attributes
			// from the receiver creator so we should temporarily include it in from
			// so as not to mutate the original while providing the desired value
			// receiver config set by the initial receiver config parser
			from.InsertString(receiverConfigAttr, receiverAttrs[receiverConfigAttr])
			temporaryReceiverConfigAttr = true
		}
	}
	from.Range(func(k string, v pcommon.Value) bool {
		if k == receiverConfigAttr {
			var configVal string
			if updatedConfig, ok := receiverAttrs[receiverUpdatedConfigAttr]; ok {
				configVal = updatedConfig
			} else {
				if updated, err := addObserverToEncodedConfig(v.AsString(), corr.observerID); err != nil {
					// log failure and continue with existing config sans observer
					e.logger.Info(fmt.Sprintf("failed adding %q to %s", corr.observerID.String(), receiverConfigAttr), zap.String("receiver.type", receiverType), zap.String("receiver.name", receiverName), zap.Error(err))
				} else {
					e.logger.Debug("Adding observer to embedded receiver config", zap.String("observer", corr.observerID.String()), zap.String("receiver.type", receiverType), zap.String("receiver.name", receiverName))
					e.correlations.UpdateAttrs(corr.receiverID, map[string]string{
						observerIDAttr:            corr.observerID.String(),
						receiverUpdatedConfigAttr: updated,
					})
					configVal = updated
				}
			}
			v = pcommon.NewValueString(configVal)
		}
		to.InsertString(k, v.AsString())
		return true
	})
	if temporaryReceiverConfigAttr {
		from.Remove(receiverConfigAttr)
	}
}

// matcherAndMatchPattern parses the provided Match and returns the matcher function
// and specified pattern to match against
func (e *evaluator) evaluateMatch(match Match, pattern, status string, receiverID config.ComponentID, endpointID observer.EndpointID) (shouldLog bool, err error) {
	var matcher func(p string) bool
	var matchPattern string
	switch {
	case match.Strict != "":
		matchPattern = match.Strict
		matcher = func(p string) bool {
			return p == match.Strict
		}
	case match.Regexp != "":
		matchPattern = match.Regexp
		var re *regexp.Regexp
		if re, err = regexp.Compile(matchPattern); err != nil {
			err = fmt.Errorf("invalid match regexp statement: %w", err)
		} else {
			matcher = re.MatchString
		}
	case match.Expr != "":
		matchPattern = match.Expr
		var program *vm.Program
		if program, err = expr.Compile(match.Expr); err != nil {
			err = fmt.Errorf("invalid match expr statement: %w", err)
		} else {
			matcher = func(p string) bool {
				ret, runErr := vm.Run(program, e.exprEnv(p))
				if runErr != nil {
					e.logger.Info(fmt.Sprintf("error running match expr %s", matchPattern), zap.Error(err))
					return false
				}
				return ret.(bool)
			}
		}
	default:
		err = fmt.Errorf("no valid match field provided")
	}
	if err != nil {
		return
	}
	shouldLog = matcher(pattern)
	if !shouldLog {
		return
	}
	if match.FirstOnly {
		loggedKey := fmt.Sprintf("%s::%s::%s::%s", endpointID, receiverID.String(), status, matchPattern)
		if _, ok := e.alreadyLogged.LoadOrStore(loggedKey, struct{}{}); ok {
			shouldLog = false
		}
	}
	return
}

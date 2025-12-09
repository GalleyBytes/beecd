{{/*
Expand the name of the chart.
*/}}
{{- define "beecd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "beecd.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "beecd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "beecd.labels" -}}
helm.sh/chart: {{ include "beecd.chart" . }}
{{ include "beecd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "beecd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "beecd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Get the database host for hive database
Auto-configures to use embedded PostgreSQL when enabled
*/}}
{{- define "beecd.hive.database.host" -}}
{{- if .Values.hiveServer.database.hive.host -}}
{{- .Values.hiveServer.database.hive.host -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "%s-postgresql" .Release.Name -}}
{{- else -}}
{{- required "hiveServer.database.hive.host is required when postgresql.enabled is false" .Values.hiveServer.database.hive.host -}}
{{- end -}}
{{- end -}}

{{/*
Get the MinIO endpoint
Auto-configures to use embedded MinIO when enabled
*/}}
{{- define "beecd.minio.endpoint" -}}
{{- if .Values.hiveServer.storage.minio.endpoint -}}
{{- .Values.hiveServer.storage.minio.endpoint -}}
{{- else if .Values.minio.enabled -}}
{{- printf "http://%s-minio:9000" .Release.Name -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}


{{/*
Hive Server labels
*/}}
{{- define "beecd.hiveServer.labels" -}}
{{ include "beecd.labels" . }}
app.kubernetes.io/component: hive-server
{{- end }}

{{- define "beecd.hiveServer.selectorLabels" -}}
{{ include "beecd.selectorLabels" . }}
app.kubernetes.io/component: hive-server
{{- end }}

{{/*
Hive HQ labels
*/}}
{{- define "beecd.hiveHq.labels" -}}
{{ include "beecd.labels" . }}
app.kubernetes.io/component: hive-hq
{{- end }}

{{- define "beecd.hiveHq.selectorLabels" -}}
{{ include "beecd.selectorLabels" . }}
app.kubernetes.io/component: hive-hq
{{- end }}

{{/*
Image name
Supports: optional registry (empty = no prefix), component tag override, global tag, chart AppVersion fallback
Tag precedence: componentTag > tag > defaultTag
*/}}
{{- define "beecd.image" -}}
{{- $registry := .registry | default "" | trimSuffix "/" -}}
{{- $repository := required "repository is required" .repository -}}
{{- $componentTag := .componentTag | default "" -}}
{{- $globalTag := .tag | default "" -}}
{{- $defaultTag := .defaultTag -}}
{{- $finalTag := default (default $defaultTag $globalTag) $componentTag -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $finalTag -}}
{{- else -}}
{{- printf "%s:%s" $repository $finalTag -}}
{{- end -}}
{{- end }}

{{/*
Default gRPC server address for agent connections.
Returns user-provided value or computed in-cluster default.
*/}}
{{- define "beecd.hiveHq.defaultGrpcServer" -}}
{{- if .Values.hiveHq.env.hiveDefaultGrpcServer -}}
{{- .Values.hiveHq.env.hiveDefaultGrpcServer -}}
{{- else -}}
{{- printf "%s-hive-server.%s.svc.cluster.local:5180" (include "beecd.fullname" .) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
Default agent image for generated agent manifests.
Returns user-provided value or computed from chart image settings.
*/}}
{{- define "beecd.hiveHq.defaultAgentImage" -}}
{{- if .Values.hiveHq.env.agentDefaultImage -}}
{{- .Values.hiveHq.env.agentDefaultImage -}}
{{- else -}}
{{- include "beecd.image" (dict "registry" .Values.image.registry "repository" "hive-agent" "componentTag" "" "tag" .Values.image.tag "defaultTag" .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

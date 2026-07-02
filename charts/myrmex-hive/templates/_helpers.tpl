{{/*
Expand the name of the chart.
*/}}
{{- define "myrmex-hive.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "myrmex-hive.fullname" -}}
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
Chart name and version label.
*/}}
{{- define "myrmex-hive.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "myrmex-hive.labels" -}}
helm.sh/chart: {{ include "myrmex-hive.chart" . }}
{{ include "myrmex-hive.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (base, without component).
*/}}
{{- define "myrmex-hive.selectorLabels" -}}
app.kubernetes.io/name: {{ include "myrmex-hive.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Gateway fullname / labels / selector labels.
*/}}
{{- define "myrmex-hive.gateway.fullname" -}}
{{- printf "%s-gateway" (include "myrmex-hive.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "myrmex-hive.gateway.labels" -}}
{{ include "myrmex-hive.labels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{- define "myrmex-hive.gateway.selectorLabels" -}}
{{ include "myrmex-hive.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Agent fullname / labels / selector labels.
*/}}
{{- define "myrmex-hive.agent.fullname" -}}
{{- printf "%s-agent" (include "myrmex-hive.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "myrmex-hive.agent.labels" -}}
{{ include "myrmex-hive.labels" . }}
app.kubernetes.io/component: agent
{{- end }}

{{- define "myrmex-hive.agent.selectorLabels" -}}
{{ include "myrmex-hive.selectorLabels" . }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Gateway image reference.
*/}}
{{- define "myrmex-hive.gateway.image" -}}
{{- $tag := .Values.gateway.image.tag | default .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repositoryPrefix .Values.gateway.image.repository $tag }}
{{- end }}

{{/*
Agent image reference.
*/}}
{{- define "myrmex-hive.agent.image" -}}
{{- $tag := .Values.agent.image.tag | default .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s/%s/%s:%s" .Values.image.registry .Values.image.repositoryPrefix .Values.agent.image.repository $tag }}
{{- end }}

{{/*
Gateway service DNS address the agent dials, unless agent.config.gateway_addr
is set explicitly.
*/}}
{{- define "myrmex-hive.gateway.addr" -}}
{{- printf "%s:%d" (include "myrmex-hive.gateway.fullname" .) (.Values.gateway.ports.ssh | int) }}
{{- end }}

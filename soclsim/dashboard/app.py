from __future__ import annotations

import os
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
import time


st.set_page_config(page_title="SOC Log Intelligence Dashboard", layout="wide")


def fetch_alerts(base_url: str, min_severity: str, limit: int = 200, ip: str | None = None, user: str | None = None):
    params = {"min_severity": min_severity, "limit": limit}
    if ip:
        params["ip"] = ip
    if user:
        params["user"] = user
    r = requests.get(f"{base_url}/alerts", params=params, timeout=10)
    r.raise_for_status()
    return r.json()


def fetch_stats(base_url: str):
    r = requests.get(f"{base_url}/stats", timeout=10)
    r.raise_for_status()
    return r.json()


def fetch_incident(base_url: str, incident_id: str):
    r = requests.get(f"{base_url}/incidents/{incident_id}", timeout=10)
    r.raise_for_status()
    return r.json()


st.sidebar.title("Settings")
base_url = st.sidebar.text_input("API base URL", value=os.environ.get("SOCLSIM_API_URL", "http://127.0.0.1:8000"))
min_sev = st.sidebar.selectbox("Min severity", ["low", "medium", "high"], index=1)
limit = st.sidebar.slider("Max alerts", 50, 500, 200, step=50)

# Auto-refresh toggle
auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
if auto_refresh:
    time.sleep(30)
    st.rerun()

colA, colB = st.columns([2, 1])

with colA:
    st.subheader("Alerts timeline")
    try:
        alerts = fetch_alerts(base_url, min_sev, limit=limit)
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        st.stop()

    if not alerts:
        st.info("No alerts yet. Ingest logs or run the generator + training first.")
    else:
        df = pd.DataFrame(alerts)
        df["start_ts"] = pd.to_datetime(df["start_ts"])
        df = df.sort_values("start_ts")
        # Use final_risk if available, otherwise score
        y_col = "final_risk" if "final_risk" in df.columns else "score"
        hover_cols = ["user", "ip", "title"]
        if "detection_type" in df.columns:
            hover_cols.append("detection_type")
        
        # Tabbed view: Scatter plot and Bar chart
        tab1, tab2 = st.tabs(["Scatter Plot", "Alerts per Minute"])
        
        with tab1:
            fig = px.scatter(
                df,
                x="start_ts",
                y=y_col,
                color="severity",
                hover_data=hover_cols,
                size=y_col,
                title="Incident scores over time",
                labels={"start_ts": "Time", y_col: "Risk Score"},
                color_discrete_map={"high": "red", "medium": "orange", "low": "yellow"},
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            # Group by minute and count alerts
            df["minute"] = df["start_ts"].dt.floor("min")
            minute_counts = df.groupby("minute", as_index=False).size()
            minute_counts.columns = ["minute", "count"]
            minute_counts = minute_counts.sort_values("minute")
            
            # Calculate rolling average (5-minute window)
            minute_counts["rolling_avg"] = minute_counts["count"].rolling(window=5, min_periods=1).mean()
            
            fig2 = px.bar(
                minute_counts,
                x="minute",
                y="count",
                labels={"minute": "Time", "count": "Alerts per Minute"},
                title="Alert Frequency Over Time"
            )
            # Add rolling average line
            fig2.add_scatter(
                x=minute_counts["minute"],
                y=minute_counts["rolling_avg"],
                mode="lines",
                name="5-Min Rolling Average",
                line=dict(color="orange", width=2)
            )
            st.plotly_chart(fig2, use_container_width=True)

        st.subheader("Latest alerts")
        display_cols = ["created_ts", "severity", "final_risk" if "final_risk" in df.columns else "score", "detection_type", "user", "ip", "title"]
        display_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(
            df[display_cols].sort_values("created_ts", ascending=False),
            use_container_width=True,
            height=360,
        )

with colB:
    st.subheader("Top risk entities")
    try:
        stats = fetch_stats(base_url)
    except Exception as e:
        st.error(f"Failed to fetch stats: {e}")
        st.stop()

    st.caption(f"Events: {stats.get('events', 0)} | Alerts: {stats.get('alerts', 0)}")

    tu = pd.DataFrame(stats.get("top_users", []))
    ti = pd.DataFrame(stats.get("top_ips", []))

    st.markdown("**Top users**")
    if len(tu):
        st.dataframe(tu, use_container_width=True, height=240)
    else:
        st.write("No user risk scores yet.")

    st.markdown("**Top IPs**")
    if len(ti):
        st.dataframe(ti, use_container_width=True, height=240)
    else:
        st.write("No IP risk scores yet.")

# Evaluation Metrics
st.subheader("Model Evaluation")
try:
    import sys
    from pathlib import Path
    # Add project root to path if not already there
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    from soclsim.evaluation.metrics import compute_detection_metrics, compute_auc_score, generate_synthetic_labels
    
    if alerts:
        # Generate synthetic labels for evaluation
        labels = generate_synthetic_labels(alerts)
        metrics = compute_detection_metrics(alerts, labels)
        auc = compute_auc_score(alerts, labels)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Precision", f"{metrics['precision']:.3f}")
        with col2:
            st.metric("Recall", f"{metrics['recall']:.3f}")
        with col3:
            st.metric("F1-Score", f"{metrics['f1']:.3f}")
        with col4:
            st.metric("AUC-ROC", f"{auc:.3f}")
        
        st.caption("Metrics computed using synthetic labels based on detection patterns and risk scores.")
    else:
        st.info("No alerts available for evaluation.")
except ImportError:
    st.info("Evaluation metrics not shown due to module import limitations. System focuses on unsupervised anomaly detection.")
except Exception as e:
    st.info("Evaluation metrics not shown due to lack of labeled attack data. System focuses on unsupervised detection.")

# Analytics section
st.subheader("Analytics")
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**Severity Distribution**")
    if alerts:
        sev_counts = pd.Series([a["severity"] for a in alerts]).value_counts()
        fig_sev = px.bar(x=sev_counts.index, y=sev_counts.values, labels={"x": "Severity", "y": "Count"})
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.write("No data")

with col2:
    st.markdown("**Detection Category Distribution**")
    if alerts:
        cats = [a.get("category", "unknown") for a in alerts]
        cat_counts = pd.Series(cats).value_counts()
        fig_cat = px.bar(x=cat_counts.index, y=cat_counts.values, labels={"x": "Category", "y": "Count"})
        st.plotly_chart(fig_cat, use_container_width=True)
    else:
        st.write("No data")

with col3:
    st.markdown("**Alerts per Hour**")
    if alerts:
        df_hour = pd.DataFrame(alerts)
        df_hour["created_ts"] = pd.to_datetime(df_hour["created_ts"])
        # Group by hour properly
        df_hour["hour"] = df_hour["created_ts"].dt.floor("H")
        hourly = df_hour.groupby("hour", as_index=False).size()
        hourly.columns = ["hour", "count"]
        
        if len(hourly) > 0:
            # Create full hour range for complete timeline
            min_hour = hourly["hour"].min()
            max_hour = hourly["hour"].max()
            # Generate all hours in range
            hour_range = pd.date_range(start=min_hour.floor("H"), end=max_hour.ceil("H"), freq="H")
            hourly_full = pd.DataFrame({"hour": hour_range})
            hourly_full = hourly_full.merge(hourly, on="hour", how="left").fillna(0)
            hourly_full["count"] = hourly_full["count"].astype(int)
            
            # Plot as histogram/bar chart for better visibility
            fig_hour = px.bar(hourly_full, x="hour", y="count", labels={"hour": "Time", "count": "Alerts"})
            fig_hour.update_layout(showlegend=False)
            st.plotly_chart(fig_hour, use_container_width=True)
        else:
            st.write("No data")
    else:
        st.write("No data")

# Alert investigation view
# Incident List View
st.subheader("Incidents")
try:
    incidents_resp = requests.get(f"{base_url}/incidents", params={"limit": 50}, timeout=10)
    incidents_resp.raise_for_status()
    incidents_list = incidents_resp.json()
    
    if incidents_list:
        inc_df = pd.DataFrame(incidents_list)
        inc_df["start_ts"] = pd.to_datetime(inc_df["start_ts"])
        st.dataframe(
            inc_df[["incident_id", "start_ts", "max_severity", "total_alerts", "primary_ip", "primary_user", "summary"]].sort_values("start_ts", ascending=False),
            use_container_width=True,
            height=300,
        )
        
        # Incident detail view
        if len(incidents_list) > 0:
            selected_inc = st.selectbox(
                "Select incident to view details",
                options=list(range(len(incidents_list))),
                format_func=lambda i: f"{incidents_list[i]['incident_id']} - {incidents_list[i]['summary']}"
            )
            if selected_inc is not None:
                inc = incidents_list[selected_inc]
                try:
                    inc_detail = fetch_incident(base_url, inc["incident_id"])
                    
                    # Incident status workflow
                    col1, col2 = st.columns(2)
                    with col1:
                        new_status = st.selectbox(
                            "Status",
                            options=["open", "investigating", "resolved", "false_positive"],
                            index=["open", "investigating", "resolved", "false_positive"].index(inc_detail.get("status", "open")),
                            key=f"status_{inc_detail['incident_id']}"
                        )
                        if new_status != inc_detail.get("status"):
                            try:
                                requests.patch(
                                    f"{base_url}/incidents/{inc_detail['incident_id']}",
                                    params={"status": new_status},
                                    timeout=10
                                )
                                st.success(f"Status updated to {new_status}")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to update status: {e}")
                    
                    with col2:
                        st.markdown(f"**Max Severity**: {inc_detail['max_severity']}")
                    
                    # Resolution reason (if resolved or false_positive)
                    if new_status in ("resolved", "false_positive"):
                        resolution_type = st.selectbox(
                            "Resolution Type",
                            options=["", "confirmed_attack", "false_positive", "benign_activity", "other"],
                            index=0,
                            key=f"res_type_{inc_detail['incident_id']}",
                            help="Select the type of resolution"
                        )
                        resolution_reason = st.text_area(
                            "Resolution Reason",
                            value=inc_detail.get("resolution_reason", ""),
                            key=f"resolution_{inc_detail['incident_id']}",
                            placeholder="Explain why this incident was resolved or marked as false positive...",
                            height=100
                        )
                        if resolution_reason != inc_detail.get("resolution_reason", "") or resolution_type:
                            if st.button("Save Resolution", key=f"save_res_{inc_detail['incident_id']}"):
                                try:
                                    final_reason = f"{resolution_type}: {resolution_reason}" if resolution_type else resolution_reason
                                    requests.patch(
                                        f"{base_url}/incidents/{inc_detail['incident_id']}",
                                        params={"resolution_reason": final_reason},
                                        timeout=10
                                    )
                                    st.success("Resolution reason saved")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Failed to save resolution: {e}")
                    
                    st.markdown(f"**Incident**: {inc_detail['incident_id']}")
                    st.markdown(f"**Time Range**: {inc_detail['start_ts']} to {inc_detail['end_ts']}")
                    st.markdown(f"**Total Alerts**: {inc_detail['total_alerts']}")
                    st.markdown(f"**Summary**: {inc_detail['summary']}")
                    
                    # Analyst notes
                    notes = st.text_area(
                        "Analyst Notes",
                        value=inc_detail.get("analyst_notes", ""),
                        key=f"notes_{inc_detail['incident_id']}",
                        height=100
                    )
                    if notes != inc_detail.get("analyst_notes", ""):
                        if st.button("Save Notes", key=f"save_{inc_detail['incident_id']}"):
                            try:
                                requests.patch(
                                    f"{base_url}/incidents/{inc_detail['incident_id']}",
                                    params={"analyst_notes": notes},
                                    timeout=10
                                )
                                st.success("Notes saved")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to save notes: {e}")
                    
                    if inc_detail.get("alerts"):
                        inc_alerts_df = pd.DataFrame(inc_detail["alerts"])
                        inc_alerts_df["created_ts"] = pd.to_datetime(inc_alerts_df["created_ts"])
                        st.dataframe(
                            inc_alerts_df[["created_ts", "severity", "detection_type", "category", "title"]].sort_values("created_ts"),
                            use_container_width=True,
                        )
                except Exception as e:
                    st.error(f"Could not load incident details: {e}")
    else:
        st.info("No incidents yet.")
except Exception as e:
    st.warning(f"Could not load incidents: {e}")

st.subheader("Alert Investigation")
if alerts:
    pick = st.selectbox("Select alert", options=list(range(len(alerts))), format_func=lambda i: alerts[i]["title"])
    a = alerts[pick]

    # Collapsible sections for investigation
    with st.expander("🔍 Risk Score Breakdown", expanded=True):
        final_risk = a.get("final_risk") or a.get("score", 0.0)
        window_score = a.get("window_score", 0.0)
        sequence_score = a.get("sequence_score", 0.0)
        
        # Color code based on risk level
        risk_color = "🔴" if final_risk > 0.8 else "🟠" if final_risk > 0.5 else "🟡"
        st.markdown(f"**Final Risk**: {risk_color} `{final_risk:.3f}`")
        st.markdown(f"**Window Anomaly Score**: `{window_score:.3f}` (Isolation Forest + Dense Autoencoder)")
        st.markdown(f"**Sequence Anomaly Score**: `{sequence_score:.3f}` (LSTM Autoencoder)")
        
        # Model agreement (how close are the two scores)
        score_diff = abs(window_score - sequence_score)
        agreement = "High" if score_diff < 0.2 else "Medium" if score_diff < 0.4 else "Low"
        agreement_color = "🟢" if agreement == "High" else "🟡" if agreement == "Medium" else "🔴"
        st.markdown(f"**Model Agreement**: {agreement_color} {agreement} (difference: {score_diff:.3f})")

    with st.expander("🛡️ Detection Information", expanded=True):
        sev = a['severity'].upper()
        sev_badge = "🔴 HIGH" if sev == "HIGH" else "🟠 MEDIUM" if sev == "MEDIUM" else "🟡 LOW"
        st.markdown(f"**Severity**: {sev_badge}")
        
        det_type = a.get('detection_type', 'unknown')
        det_type_display = det_type.replace('_', ' ').title()
        st.markdown(f"**Detection Type**: `{det_type_display}`")
        st.markdown(f"**Category**: `{a.get('category', 'unknown').replace('_', ' ').title()}`")

    with st.expander("🎯 MITRE ATT&CK Mapping", expanded=False):
        mitre_list = a.get("mitre", [])
    if mitre_list:
        mitre_df = pd.DataFrame(mitre_list)
        # Color code tactics
        tactic_colors = {
            "Credential Access": "🔑",
            "Lateral Movement": "➡️",
            "Command and Control": "🌐",
            "Exfiltration": "📤",
            "Defense Evasion": "🛡️",
            "Persistence": "🔒",
            "Discovery": "🔍",
        }
        mitre_df["tactic_icon"] = mitre_df["tactic"].map(lambda t: tactic_colors.get(t, "⚙️"))
        display_df = mitre_df[["tactic_icon", "technique_id", "technique", "tactic"]]
        st.dataframe(display_df, use_container_width=True)
    else:
        st.write("No MITRE mapping available")

    # Explanation
    st.markdown("### Explanation")
    st.code(a.get("explanation", ""), language="text")

    with st.expander("📊 Top Contributing Features", expanded=False):
        top_feat = a.get("top_features", [])
    if top_feat:
        feat_df = pd.DataFrame(top_feat)
        # Format display: show percentile if available
        display_cols = ["feature", "value"]
        if "percentile" in feat_df.columns:
            display_cols.append("percentile")
        if "z_score" in feat_df.columns:
            display_cols.append("z_score")
        if "attribution" in feat_df.columns:
            display_cols.append("attribution")
        
        # Add formatted percentile column
        if "percentile" in feat_df.columns:
            feat_df["percentile_display"] = feat_df["percentile"].apply(
                lambda p: f"{p:.1f}th percentile" if p != 50.0 else "median"
            )
            display_cols.append("percentile_display")
        
        st.dataframe(feat_df[display_cols], use_container_width=True)
        
        # Show explanation
        if "percentile" in feat_df.columns:
            st.caption("Percentiles are computed from training data distribution. Higher percentiles indicate more anomalous values.")
    else:
        st.write("No feature attribution available")

    # Previous alerts for same IP/user
    st.markdown("### Related Alerts")
    related_alerts = []
    if a.get("ip"):
        try:
            related = fetch_alerts(base_url, "low", limit=20, ip=a["ip"])
            related_alerts.extend([r for r in related if r["alert_id"] != a["alert_id"]])
        except Exception:
            pass
    if a.get("user"):
        try:
            related = fetch_alerts(base_url, "low", limit=20, user=a["user"])
            related_alerts.extend([r for r in related if r["alert_id"] != a["alert_id"] and r not in related_alerts])
        except Exception:
            pass

    if related_alerts:
        rel_df = pd.DataFrame(related_alerts)
        rel_df["created_ts"] = pd.to_datetime(rel_df["created_ts"])
        st.dataframe(
            rel_df[["created_ts", "severity", "final_risk" if "final_risk" in rel_df.columns else "score", "detection_type", "title"]].sort_values("created_ts", ascending=False),
            use_container_width=True,
            height=200,
        )
    else:
        st.write("No related alerts found")

    # Incident timeline (if incident_id exists)
    if a.get("incident_id_str") or a.get("incident_id"):
        st.markdown("### Incident Timeline")
        try:
            # Use string ID if available, otherwise try integer lookup
            inc_id = a.get("incident_id_str") or str(a.get("incident_id", ""))
            if inc_id:
                incident = fetch_incident(base_url, inc_id)
            st.markdown(f"**Incident ID**: {incident['incident_id']}")
            st.markdown(f"**Total Alerts**: {incident['total_alerts']}")
            st.markdown(f"**Max Severity**: {incident['max_severity']}")
            st.markdown(f"**Summary**: {incident['summary']}")

            if incident.get("alerts"):
                inc_alerts_df = pd.DataFrame(incident["alerts"])
                inc_alerts_df["created_ts"] = pd.to_datetime(inc_alerts_df["created_ts"])
                st.dataframe(
                    inc_alerts_df[["created_ts", "severity", "detection_type", "title"]].sort_values("created_ts"),
                    use_container_width=True,
                    height=200,
                )
        except Exception as e:
            st.write(f"Could not load incident details: {e}")

    with st.expander("📋 Evidence Timeline", expanded=False):
        evidence = a.get("evidence", [])
        if evidence:
            # Show first 10 by default, allow expansion
            show_all = st.checkbox("Show all evidence", value=False, key=f"evidence_{a['alert_id']}")
            num_to_show = len(evidence) if show_all else min(10, len(evidence))
            
            ev_df = pd.DataFrame(evidence[:num_to_show])
            if "ts" in ev_df.columns:
                ev_df["ts"] = pd.to_datetime(ev_df["ts"])
                ev_df = ev_df.sort_values("ts")
                display_cols = ["ts", "source", "event_type", "user", "ip"]
                display_cols = [c for c in display_cols if c in ev_df.columns]
                st.dataframe(ev_df[display_cols], use_container_width=True, height=min(400, num_to_show * 40))
            else:
                # Fallback: show as JSON if no ts column
                st.json(evidence[:num_to_show])
            
            if len(evidence) > num_to_show:
                st.caption(f"Showing {num_to_show} of {len(evidence)} events. Check 'Show all evidence' to see all.")
        else:
            st.write("No evidence available")



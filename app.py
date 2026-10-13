"""
LogSense AI - Agentic Log Analysis and Incident Intelligence Platform
Frontend Dashboard powered by Streamlit, Custom CSS, and Plotly.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone
import os
import io

from src.models import AnalysisSession, Incident, LogEvent, AgentResult
from src.agent_orchestrator import AgentOrchestrator
from src.database import DatabaseManager
from src.synthetic_generator import generate_synthetic_logs, write_sample_log_file

# Streamlit Page Config
st.set_page_config(
    page_title="Agentic AI Log Analysis System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# CUSTOM CSS INJECTION - Professional Observability Aesthetic
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
/* Main container adjustments */
.main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    padding-left: 2rem;
    padding-right: 2rem;
}

/* Glassmorphic Metric Cards */
.metric-card {
    background: linear-gradient(135deg, rgba(22, 27, 34, 0.95), rgba(13, 17, 23, 0.95));
    border: 1px solid rgba(48, 54, 61, 0.9);
    border-radius: 10px;
    padding: 16px 20px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    margin-bottom: 12px;
}
.metric-title {
    font-size: 0.82rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #8B949E;
    margin-bottom: 4px;
}
.metric-value {
    font-size: 1.85rem;
    font-weight: 700;
    color: #F0F6FC;
    line-height: 1.2;
}
.metric-subtitle {
    font-size: 0.78rem;
    color: #58A6FF;
    margin-top: 4px;
}

/* Severity Badges */
.badge-critical {
    background-color: rgba(248, 81, 73, 0.2);
    color: #FF7B72;
    border: 1px solid #F85149;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
    display: inline-block;
}
.badge-high {
    background-color: rgba(210, 153, 34, 0.2);
    color: #E3B341;
    border: 1px solid #D29922;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
    display: inline-block;
}
.badge-medium {
    background-color: rgba(187, 128, 9, 0.2);
    color: #D29922;
    border: 1px solid #9E6A03;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
    display: inline-block;
}
.badge-low {
    background-color: rgba(56, 139, 253, 0.15);
    color: #58A6FF;
    border: 1px solid #1F6FEB;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
    display: inline-block;
}
.badge-reviewed {
    background-color: rgba(46, 160, 67, 0.2);
    color: #3FB950;
    border: 1px solid #2EA043;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
    display: inline-block;
}

/* Agent Workflow Box */
.agent-node {
    background: #161B22;
    border-left: 4px solid #58A6FF;
    border-top: 1px solid #30363D;
    border-right: 1px solid #30363D;
    border-bottom: 1px solid #30363D;
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 12px;
}
.agent-node-title {
    font-size: 0.98rem;
    font-weight: 600;
    color: #F0F6FC;
}
.agent-node-time {
    font-size: 0.78rem;
    color: #7EE787;
    float: right;
    font-family: monospace;
}
.agent-node-desc {
    font-size: 0.85rem;
    color: #8B949E;
    margin-top: 6px;
}

/* Evidence snippet block */
.evidence-box {
    background-color: #0D1117;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: monospace;
    font-size: 0.80rem;
    color: #C9D1D9;
    margin-top: 6px;
    overflow-x: auto;
}

/* Header branding */
.platform-title {
    font-size: 1.15rem;
    font-weight: 800;
    line-height: 1.35;
    background: linear-gradient(90deg, #58A6FF, #BC8CFF);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    display: inline-block;
    margin-bottom: 1rem;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# APPLICATION STATE & SINGLETONS
# -----------------------------------------------------------------------------
@st.cache_resource
def get_db_manager() -> DatabaseManager:
    return DatabaseManager()

@st.cache_resource
def get_orchestrator() -> AgentOrchestrator:
    return AgentOrchestrator()

db = get_db_manager()
orchestrator = get_orchestrator()

if "session" not in st.session_state:
    st.session_state.session = None

if "selected_incident_id" not in st.session_state:
    st.session_state.selected_incident_id = None


# -----------------------------------------------------------------------------
# SIDEBAR NAVIGATION & CONTROLS
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown('<div class="platform-title">Agentic AI Log Analysis System</div>', unsafe_allow_html=True)

    menu = st.radio(
        "Navigation",
        [
            "📊 Overview",
            "📁 Upload Logs",
            "🔍 Operational Incident Explorer",
            "🤖 Agent Workflow",
            "🔬 Root Cause Analysis",
            "📑 Reports & Export",
            "⚙️ Settings & History",
        ],
        index=0,
    )

    st.divider()

    # Quick Demo Actions
    st.markdown("### ⚡ Quick Start")
    if st.button("Generate Demo Logs (5,000)", use_container_width=True, type="primary"):
        with st.spinner("Generating 5,000 synthetic log records across 7 microservices..."):
            demo_logs = generate_synthetic_logs(num_logs=5000)
            progress_bar = st.progress(0.0)
            status_text = st.empty()

            def update_ui(msg, pct):
                status_text.text(msg)
                progress_bar.progress(pct)

            new_session = orchestrator.run_pipeline(
                log_content=demo_logs,
                filename="synthetic_demo_logs.log",
                progress_callback=update_ui
            )
            db.save_session(new_session)
            st.session_state.session = new_session
            st.success(f"Analysis complete! Detected {len(new_session.incidents)} incidents.")
            st.rerun()

    if st.button("Load Built-in Sample File", use_container_width=True):
        sample_path = os.path.join(os.path.dirname(__file__), "data", "sample_logs.log")
        if not os.path.exists(sample_path):
            sample_path = write_sample_log_file()

        with open(sample_path, "r", encoding="utf-8") as f:
            content = f.read()

        with st.spinner("Analyzing data/sample_logs.log with 6 Agents..."):
            new_session = orchestrator.run_pipeline(log_content=content, filename="sample_logs.log")
            db.save_session(new_session)
            st.session_state.session = new_session
            st.success(f"Loaded and analyzed {new_session.total_logs} logs.")
            st.rerun()

    st.divider()
    # Database stats summary in sidebar
    stats = db.get_stats()
    st.markdown(
        f"<small style='color:#8B949E'>DB Records: {stats['total_sessions']} sessions | {stats['total_incidents']} incidents | {stats['database_size_kb']} KB</small>",
        unsafe_allow_html=True,
    )


# Helper function to render KPI Cards
def render_kpi_cards(session: AnalysisSession):
    col1, col2, col3, col4 = st.columns(4)

    total_logs = session.total_logs if session else 0
    total_incidents = len(session.incidents) if session else 0
    critical_incidents = session.critical_count if session else 0
    reviewed_incidents = sum(1 for i in session.incidents if i.is_reviewed) if session else 0

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Total Log Events</div>
            <div class="metric-value">{total_logs:,}</div>
            <div class="metric-subtitle">Parsed & Ingested</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Incidents Detected</div>
            <div class="metric-value">{total_incidents:,}</div>
            <div class="metric-subtitle">Correlated Clusters</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Critical Severity</div>
            <div class="metric-value" style="color: #FF7B72;">{critical_incidents}</div>
            <div class="metric-subtitle">Immediate Attention</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Reviewed Incidents</div>
            <div class="metric-value" style="color: #3FB950;">{reviewed_incidents} <span style="font-size:1rem;color:#8B949E">/ {total_incidents}</span></div>
            <div class="metric-subtitle">Engineering Audited</div>
        </div>
        """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 1. OVERVIEW PAGE
# -----------------------------------------------------------------------------
if menu == "📊 Overview":
    st.title("Platform Overview & Observability Metrics")

    session = st.session_state.session
    if not session:
        st.info("👋 Welcome to the **Agentic AI Log Analysis System**. No log analysis session is currently loaded. Click **'Generate Demo Logs'** or upload a log file to begin.")
        st.stop()

    render_kpi_cards(session)

    # Visualizations Row 1
    col_chart1, col_chart2 = st.columns([1, 1])

    with col_chart1:
        st.subheader("Incident Severity Breakdown")
        sev_counts = {
            "CRITICAL": session.critical_count,
            "HIGH": session.high_count,
            "MEDIUM": session.medium_count,
            "LOW": session.low_count,
        }
        df_sev = pd.DataFrame([{"Severity": k, "Count": v} for k, v in sev_counts.items() if v > 0])
        if not df_sev.empty:
            colors = {"CRITICAL": "#F85149", "HIGH": "#D29922", "MEDIUM": "#E3B341", "LOW": "#58A6FF"}
            fig_sev = px.pie(
                df_sev,
                names="Severity",
                values="Count",
                hole=0.6,
                color="Severity",
                color_discrete_map=colors,
            )
            fig_sev.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#C9D1D9",
                margin=dict(t=20, b=20, l=20, r=20),
                height=280,
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.caption("No incidents detected.")

    with col_chart2:
        st.subheader("Failures by Application / Service")
        svc_counts = {}
        for inc in session.incidents:
            svc_counts[inc.service] = svc_counts.get(inc.service, 0) + 1
        df_svc = pd.DataFrame([{"Service": k, "Incidents": v} for k, v in svc_counts.items()]).sort_values("Incidents", ascending=True)
        if not df_svc.empty:
            fig_svc = px.bar(
                df_svc,
                x="Incidents",
                y="Service",
                orientation="h",
                color="Incidents",
                color_continuous_scale="Purp",
            )
            fig_svc.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#C9D1D9",
                margin=dict(t=20, b=20, l=20, r=20),
                height=280,
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_svc, use_container_width=True)
        else:
            st.caption("No service failures recorded.")

    # Visualizations Row 2: Incident Categories & Timeline
    col_chart3, col_chart4 = st.columns([1, 1])

    with col_chart3:
        st.subheader("Incident Categories Distribution")
        cat_counts = {}
        for inc in session.incidents:
            cat_counts[inc.category] = cat_counts.get(inc.category, 0) + 1
        df_cat = pd.DataFrame([{"Category": k.replace("_", " "), "Count": v} for k, v in cat_counts.items()]).sort_values("Count", ascending=False)
        if not df_cat.empty:
            fig_cat = px.bar(
                df_cat,
                x="Category",
                y="Count",
                color="Count",
                color_continuous_scale="Teal",
            )
            fig_cat.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#C9D1D9",
                margin=dict(t=20, b=20, l=20, r=20),
                height=280,
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_cat, use_container_width=True)

    with col_chart4:
        st.subheader("Correlated Events Timeline")
        timeline_data = []
        for inc in session.incidents:
            for ev in inc.correlated_events:
                timeline_data.append({
                    "Timestamp": ev.timestamp,
                    "Severity": inc.severity,
                    "Service": ev.service,
                    "Incident": inc.id,
                })
        if timeline_data:
            df_tl = pd.DataFrame(timeline_data)
            fig_tl = px.histogram(
                df_tl,
                x="Timestamp",
                color="Severity",
                nbins=25,
                color_discrete_map={"CRITICAL": "#F85149", "HIGH": "#D29922", "MEDIUM": "#E3B341", "LOW": "#58A6FF"},
            )
            fig_tl.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#C9D1D9",
                margin=dict(t=20, b=20, l=20, r=20),
                height=280,
            )
            st.plotly_chart(fig_tl, use_container_width=True)

    # Active Incidents Table Preview
    st.subheader("Active Incidents Registry")
    if session.incidents:
        table_rows = []
        for inc in session.incidents:
            table_rows.append({
                "Incident ID": inc.id,
                "Severity": inc.severity,
                "Title": inc.title,
                "Service": inc.service,
                "Endpoint": inc.endpoint or "N/A",
                "Events": inc.event_count,
                "Confidence": f"{inc.confidence_score * 100:.0f}%",
                "Status": "✅ Reviewed" if inc.is_reviewed else "⚠️ Open",
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No active incidents found.")


# -----------------------------------------------------------------------------
# 2. UPLOAD LOGS PAGE
# -----------------------------------------------------------------------------
elif menu == "📁 Upload Logs":
    st.title("Log File Ingestion & Parsing")
    st.markdown("Upload `.log`, `.txt`, or `.csv` log files to run the multi-agent incident intelligence workflow.")

    uploaded_file = st.file_uploader("Select log file", type=["log", "txt", "csv"])

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        process_btn = st.button("Analyze Uploaded File", type="primary", disabled=uploaded_file is None)

    if process_btn and uploaded_file is not None:
        file_bytes = uploaded_file.read()
        try:
            content = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content = file_bytes.decode("latin-1", errors="replace")

        prog = st.progress(0.0)
        status_box = st.empty()

        def update_progress(msg, pct):
            status_box.text(msg)
            prog.progress(pct)

        session = orchestrator.run_pipeline(
            log_content=content,
            filename=uploaded_file.name,
            progress_callback=update_progress
        )
        db.save_session(session)
        st.session_state.session = session

        st.success(f"Analysis completed successfully! Ingested {session.total_logs} events and identified {len(session.incidents)} operational incidents.")
        st.rerun()

    # Log Preview if session is loaded
    if st.session_state.session and st.session_state.session.parsed_logs:
        st.divider()
        st.subheader("Parsed Log Events Viewer")
        logs = st.session_state.session.parsed_logs

        filter_col1, filter_col2, filter_col3 = st.columns(3)
        with filter_col1:
            lvl_filter = st.multiselect("Filter by Level", options=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"], default=["WARN", "ERROR", "CRITICAL"])
        with filter_col2:
            services_available = sorted(list(set(e.service for e in logs)))
            svc_filter = st.multiselect("Filter by Service", options=services_available, default=services_available[:5] if len(services_available) > 5 else services_available)
        with filter_col3:
            search_query = st.text_input("Search Log Messages", "")

        filtered = [
            e for e in logs
            if (not lvl_filter or e.level in lvl_filter)
            and (not svc_filter or e.service in svc_filter)
            and (not search_query or search_query.lower() in e.message.lower())
        ]

        st.write(f"Displaying **{len(filtered)}** of **{len(logs)}** log entries:")

        df_display = pd.DataFrame([
            {
                "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Level": e.level,
                "Service": e.service,
                "Endpoint": e.endpoint or "-",
                "Status": e.status_code if e.status_code else "-",
                "Latency (ms)": f"{e.response_time_ms:.1f}" if e.response_time_ms else "-",
                "Message": e.message[:140],
            }
            for e in filtered[:500]  # view first 500 for performance
        ])
        st.dataframe(df_display, use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# 3. INCIDENT EXPLORER PAGE
# -----------------------------------------------------------------------------
elif menu == "🔍 Operational Incident Explorer":
    st.title("Operational Incident Explorer")
    session = st.session_state.session

    saved_sessions = db.list_sessions()
    if saved_sessions:
        active_session_id = session.session_id if session else saved_sessions[0]["session_id"]
        session_index = next(
            (index for index, item in enumerate(saved_sessions) if item["session_id"] == active_session_id),
            0,
        )
        selected_session_id = st.selectbox(
            "Analysis session",
            options=[item["session_id"] for item in saved_sessions],
            index=session_index,
            format_func=lambda session_id: next(
                f"{item['filename']} · {item['created_at'][:16].replace('T', ' ')} · {item['total_incidents']} incidents"
                for item in saved_sessions
                if item["session_id"] == session_id
            ),
            key=f"incident_explorer_session_{active_session_id}",
        )
        if not session or session.session_id != selected_session_id:
            session = db.get_session(selected_session_id)
            st.session_state.session = session

    if not session:
        st.info("No saved analysis sessions yet. Generate demo logs or upload a log file to start an investigation.")
        st.stop()

    if not session.incidents:
        st.info("This analysis session contains no detected incidents. Choose another session or analyze more logs.")
        st.stop()

    st.caption(f"Session `{session.session_id}` · {session.filename} · {session.created_at.strftime('%Y-%m-%d %H:%M UTC')}")

    critical_count = sum(incident.severity == "CRITICAL" for incident in session.incidents)
    open_count = sum(not incident.is_reviewed for incident in session.incidents)
    reviewed_count = len(session.incidents) - open_count
    summary_cols = st.columns(4)
    summary_cols[0].metric("Incidents", len(session.incidents))
    summary_cols[1].metric("Critical", critical_count)
    summary_cols[2].metric("Open review", open_count)
    summary_cols[3].metric("Reviewed", reviewed_count)

    search_col, sort_col = st.columns([2, 1])
    with search_col:
        search_query = st.text_input("Search incidents", placeholder="Search ID, title, service, endpoint, or detection reason")
    with sort_col:
        sort_order = st.selectbox("Sort by", ["Newest", "Oldest", "Highest severity", "Most events"])

    filter_cols = st.columns(4)
    with filter_cols[0]:
        sel_severities = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with filter_cols[1]:
        categories = sorted({incident.category for incident in session.incidents})
        sel_categories = st.multiselect("Category", categories, default=categories)
    with filter_cols[2]:
        services = sorted({incident.service for incident in session.incidents})
        sel_services = st.multiselect("Service", services, default=services)
    with filter_cols[3]:
        review_filter = st.selectbox("Review status", ["All", "Open", "Reviewed"])

    normalized_query = search_query.strip().lower()
    filtered_incidents = [
        incident for incident in session.incidents
        if (not sel_severities or incident.severity in sel_severities)
        and (not sel_categories or incident.category in sel_categories)
        and (not sel_services or incident.service in sel_services)
        and (
            review_filter == "All"
            or (review_filter == "Open" and not incident.is_reviewed)
            or (review_filter == "Reviewed" and incident.is_reviewed)
        )
        and (
            not normalized_query
            or normalized_query in " ".join((
                incident.id,
                incident.title,
                incident.category,
                incident.service,
                incident.endpoint or "",
                incident.detection_reason,
            )).lower()
        )
    ]

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if sort_order == "Newest":
        filtered_incidents.sort(key=lambda incident: incident.first_seen, reverse=True)
    elif sort_order == "Oldest":
        filtered_incidents.sort(key=lambda incident: incident.first_seen)
    elif sort_order == "Highest severity":
        filtered_incidents.sort(key=lambda incident: (severity_rank.get(incident.severity, 4), incident.first_seen), reverse=False)
    else:
        filtered_incidents.sort(key=lambda incident: incident.event_count, reverse=True)

    st.markdown(f"#### {len(filtered_incidents)} matching incidents")

    visible_ids = {incident.id for incident in filtered_incidents}
    if st.session_state.selected_incident_id not in visible_ids:
        st.session_state.selected_incident_id = filtered_incidents[0].id if filtered_incidents else None

    col_list, col_details = st.columns([0.9, 1.5], gap="large")

    with col_list:
        if not filtered_incidents:
            st.warning("No incidents match these filters.")
        for incident in filtered_incidents:
            is_selected = incident.id == st.session_state.selected_incident_id
            if st.button(
                f"{incident.severity} · {incident.id}\n{incident.title}",
                key=f"btn_{incident.id}",
                type="primary" if is_selected else "secondary",
                use_container_width=True,
            ):
                st.session_state.selected_incident_id = incident.id
            st.caption(
                f"{incident.service} · {incident.event_count} events · "
                f"{'Reviewed' if incident.is_reviewed else 'Open'}"
            )

    with col_details:
        active_inc = next(
            (incident for incident in filtered_incidents if incident.id == st.session_state.selected_incident_id),
            None,
        )

        if active_inc:
            st.markdown(f"### {active_inc.title}")
            st.caption(f"{active_inc.id} · {active_inc.category.replace('_', ' ').title()} · {active_inc.detection_method}")
            detail_metrics = st.columns(3)
            detail_metrics[0].metric("Severity", active_inc.severity)
            detail_metrics[1].metric("Events", active_inc.event_count)
            detail_metrics[2].metric("Confidence", f"{active_inc.confidence_score:.0%}")
            st.markdown(
                f"**Service:** `{active_inc.service}` · **Endpoint:** `{active_inc.endpoint or 'N/A'}`  \n"
                f"**First seen:** {active_inc.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} · "
                f"**Last seen:** {active_inc.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            st.info(active_inc.detection_reason or "No detection rationale was recorded.")

            with st.expander(f"Possible causes ({len(active_inc.possible_root_causes)})", expanded=bool(active_inc.possible_root_causes)):
                if active_inc.possible_root_causes:
                    for cause in active_inc.possible_root_causes:
                        st.markdown(f"**{cause.confidence} confidence · {cause.confidence_score:.0%}**  \n{cause.hypothesis}")
                        if cause.uncertainty_note:
                            st.caption(cause.uncertainty_note)
                        for evidence in cause.evidence:
                            st.code(evidence, language=None)
                else:
                    st.caption("No root-cause hypotheses were produced for this incident.")

            with st.expander(f"Recommended actions ({len(active_inc.recommended_actions)})"):
                if active_inc.recommended_actions:
                    for action in active_inc.recommended_actions:
                        st.markdown(f"**{action.urgency} · {action.category}**  \n{action.action}")
                        if action.diagnostic_command:
                            st.code(action.diagnostic_command, language="bash")
                else:
                    st.caption("No recommended actions were produced for this incident.")

            # Engineer Review & Notes Interaction
            st.markdown("#### On-call review")
            with st.form(key=f"review_form_{active_inc.id}"):
                is_rev = st.checkbox("Mark as reviewed", value=active_inc.is_reviewed)
                notes = st.text_area("Investigation notes", value=active_inc.review_notes, placeholder="Record containment actions, ticket links, or confirmation notes.")
                save_btn = st.form_submit_button("Save review", type="primary")

                if save_btn:
                    active_inc.is_reviewed = is_rev
                    active_inc.review_notes = notes
                    active_inc.status = "REVIEWED" if is_rev else "INVESTIGATING"
                    db.update_incident_review(active_inc.id, is_rev, notes)
                    st.success(f"Incident {active_inc.id} status successfully saved to SQLite database!")
                    st.rerun()

            # Correlated Log Events
            st.markdown("#### Correlated log events")
            if active_inc.correlated_events:
                ev_data = [
                    {
                        "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "Level": e.level,
                        "Service": e.service,
                        "Message": e.message[:120],
                    }
                    for e in active_inc.correlated_events[:15]
                ]
                st.dataframe(pd.DataFrame(ev_data), use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# 4. AGENT WORKFLOW PAGE
# -----------------------------------------------------------------------------
elif menu == "🤖 Agent Workflow":
    st.title("Multi-Agent Orchestration & ML Transparency")
    session = st.session_state.session

    if not session or not session.agent_results:
        st.info("No agent execution data available. Run an analysis session first.")
        st.stop()

    st.markdown("Inspect inputs, outputs, execution latencies, and findings for each of the 6 specialized AI agents:")

    agents = [
        ("Log Parser Agent", "1. Ingests raw .log, .txt, .csv streams, parses timestamps, levels, services, and endpoints."),
        ("Incident Detection Agent", "2. Heuristic rules + Scikit-Learn TF-IDF classifier to detect anomalies and assign severities."),
        ("Event Correlation Agent", "3. Groups related anomalous events using sliding temporal windows, endpoints, and trace links."),
        ("Root Cause Investigation Agent", "4. Reconstructs causal event sequences to formulate evidence-based root cause hypotheses."),
        ("Resolution Recommendation Agent", "5. Recommends tactical containment steps, diagnostic commands, and preventive runbooks."),
        ("Incident Report Agent", "6. Compiles comprehensive post-mortem audit reports in TXT, CSV, and JSON formats."),
    ]

    for agent_name, agent_desc in agents:
        res = session.agent_results.get(agent_name)
        if not res:
            continue

        status_icon = "🟢" if res.status == "SUCCESS" else ("🟡" if res.status == "WARNING" else "🔴")
        with st.expander(f"{status_icon} **{agent_name}** ({res.execution_time_ms:.1f} ms) — {res.status}", expanded=True):
            st.caption(agent_desc)
            st.markdown(f"**Input Summary:** {res.input_summary}")
            st.markdown(f"**Output Summary:** {res.output_summary}")

            st.markdown("**Key Findings & Conclusions:**")
            for f in res.findings:
                st.markdown(f"- {f}")

            # Special ML Model Evaluation view for Agent 2
            if agent_name == "Incident Detection Agent" and "ml_model_metrics" in res.details:
                ml = res.details["ml_model_metrics"]
                st.markdown("#### 🔬 Supervised ML Classifier Validation Metrics")
                ml_cols = st.columns(4)
                ml_cols[0].metric("Model Accuracy", f"{ml.get('accuracy', 0):.2%}")
                ml_cols[1].metric("Precision", f"{ml.get('precision', 0):.2%}")
                ml_cols[2].metric("Recall", f"{ml.get('recall', 0):.2%}")
                ml_cols[3].metric("F1-Score", f"{ml.get('f1_score', 0):.2%}")
                st.caption(f"Architecture: {ml.get('model_type', 'TF-IDF + LogisticRegression')} | Evaluated on holdout test set with stratified sampling.")


# -----------------------------------------------------------------------------
# 5. ROOT CAUSE ANALYSIS PAGE
# -----------------------------------------------------------------------------
elif menu == "🔬 Root Cause Analysis":
    st.title("Root Cause Investigation & Diagnostics")
    session = st.session_state.session

    if not session or not session.incidents:
        st.info("No active incidents to investigate.")
        st.stop()

    st.markdown("""
    > [!IMPORTANT]
    > **Scientific Observability Standard:** All root cause hypotheses are generated based on actual log evidence.
    > In accordance with reliable SRE practices, hypotheses are explicitly designated as **Possible Causes** awaiting verification.
    """)

    # Select incident
    inc_options = {f"[{i.severity}] {i.id} - {i.title}": i.id for i in session.incidents}
    selected_label = st.selectbox("Select Incident for In-Depth Root Cause Analysis", list(inc_options.keys()))
    inc_id = inc_options[selected_label]
    incident = next(i for i in session.incidents if i.id == inc_id)

    st.subheader(f"Causal Investigation: {incident.title}")

    # Root Cause Hypotheses
    st.markdown("### 🧩 Possible Root Causes (Evidence-Supported)")
    if not incident.possible_root_causes:
        st.warning("No root cause hypotheses could be formulated from the available logs.")
    else:
        for idx, hyp in enumerate(incident.possible_root_causes, start=1):
            conf_badge = f"<span class='badge-{hyp.confidence.lower()}'>{hyp.confidence.upper()} CONFIDENCE ({hyp.confidence_score*100:.0f}%)</span>"
            st.markdown(f"""
            <div style="background:#161B22; border:1px solid #30363D; border-radius:8px; padding:16px; margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:700; font-size:1.1rem; color:#F0F6FC;">Hypothesis #{idx}</span>
                    {conf_badge}
                </div>
                <div style="margin-top:8px; font-size:0.95rem; color:#C9D1D9;">{hyp.hypothesis}</div>
            </div>
            """, unsafe_allow_html=True)

            if hyp.uncertainty_note:
                st.markdown(f"**Diagnostic Uncertainty / Missing Context:**")
                st.info(f"⚠️ {hyp.uncertainty_note}")

            if hyp.evidence:
                st.markdown(f"**Supporting Log Evidence ({len(hyp.evidence)} lines):**")
                for ev_line in hyp.evidence:
                    st.code(ev_line, language="bash")

    st.divider()

    # Troubleshooting & Recommended Actions
    st.markdown("### 🛠️ Recommended Troubleshooting Runbook")
    if not incident.recommended_actions:
        st.info("No troubleshooting steps recommended.")
    else:
        for idx, act in enumerate(incident.recommended_actions, start=1):
            urg_color = "#F85149" if act.urgency == "Immediate" else ("#D29922" if act.urgency == "Short-term" else "#58A6FF")
            st.markdown(f"""
            <div style="background:#0D1117; border-left:4px solid {urg_color}; border:1px solid #30363D; border-radius:6px; padding:12px; margin-bottom:10px;">
                <span style="font-weight:700; color:{urg_color}; font-size:0.85rem;">[{act.urgency.upper()}]</span>
                <span style="color:#8B949E; font-size:0.85rem;">({act.category})</span>
                <div style="color:#F0F6FC; font-weight:600; margin-top:4px;">{act.action}</div>
            </div>
            """, unsafe_allow_html=True)

            if act.diagnostic_command:
                st.markdown(f"*Copy-ready diagnostic command:*")
                st.code(act.diagnostic_command, language="bash")


# -----------------------------------------------------------------------------
# 6. REPORTS & EXPORT PAGE
# -----------------------------------------------------------------------------
elif menu == "📑 Reports & Export":
    st.title("Post-Incident Reports & Export")
    session = st.session_state.session

    if not session:
        st.info("No session available to generate reports. Please analyze logs first.")
        st.stop()

    # Retrieve compiled reports from report agent details
    report_agent_res = session.agent_results.get("Incident Report Agent")
    compiled_reports = report_agent_res.details.get("compiled_reports", {}) if report_agent_res else {}

    txt_report = compiled_reports.get("txt", "")
    csv_report = compiled_reports.get("csv", "")
    json_report = compiled_reports.get("json", "")

    st.markdown("Download formal post-incident reports in multiple formats for engineering reviews, compliance, or Jira/ServiceNow record tracking:")

    col_d1, col_d2, col_d3 = st.columns(3)
    with col_d1:
        st.download_button(
            label="📄 Download Plain Text Report (.txt)",
            data=txt_report,
            file_name=f"incident_report_{session.session_id}.txt",
            mime="text/plain",
            use_container_width=True,
        )
    with col_d2:
        st.download_button(
            label="📊 Download CSV Incident Registry (.csv)",
            data=csv_report,
            file_name=f"incidents_{session.session_id}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with col_d3:
        st.download_button(
            label="Structured JSON Audit (.json)",
            data=json_report,
            file_name=f"audit_report_{session.session_id}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.divider()
    st.subheader("Report preview")
    st.text_area("Report preview", value=txt_report, height=450, label_visibility="collapsed")

# -----------------------------------------------------------------------------
# 7. SETTINGS & HISTORY PAGE
# -----------------------------------------------------------------------------
elif menu == "⚙️ Settings & History":
    st.title("System Settings & Analysis History")

    st.subheader("Previous Analysis Sessions (SQLite)")
    sessions = db.list_sessions(limit=20)

    if sessions:
        df_sess = pd.DataFrame([
            {
                "Session ID": s["session_id"],
                "Log File": s["filename"],
                "Created At": s["created_at"][:19],
                "Total Logs": s["total_logs"],
                "Incidents": s["total_incidents"],
                "Critical": s["critical_count"],
                "High": s["high_count"],
            }
            for s in sessions
        ])
        st.dataframe(df_sess, use_container_width=True, hide_index=True)

        selected_sess_id = st.selectbox("Reopen Previous Session from Database", [s["session_id"] for s in sessions])
        if st.button("Load Selected Session", type="primary"):
            loaded = db.get_session(selected_sess_id)
            if loaded:
                st.session_state.session = loaded
                st.success(f"Loaded session '{selected_sess_id}' with {len(loaded.incidents)} incidents.")
                st.rerun()
    else:
        st.info("No prior sessions stored in SQLite database.")

    st.divider()

    st.subheader("Database Maintenance")
    stats = db.get_stats()
    st.write(f"Database Path: `{db.db_path}`")
    st.write(f"Total Stored Sessions: **{stats['total_sessions']}** | Incidents: **{stats['total_incidents']}** | Correlated Log Events: **{stats['total_events']}**")

    if st.button("⚠️ Clear All Historical Data", type="secondary"):
        db.clear_all_data()
        st.session_state.session = None
        st.success("Cleared all stored SQLite records.")
        st.rerun()

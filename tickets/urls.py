from django.urls import path

from . import api
from . import views

urlpatterns = [
    path("", views.ticket_list, name="ticket-list"),
    path("api/tickets/", api.api_ticket_create, name="api-ticket-create"),
    path("api/tickets/<int:pk>/", api.api_ticket_detail, name="api-ticket-detail"),
    path("api/tickets/<int:pk>/messages/", api.api_ticket_message, name="api-ticket-message"),
    path("api/tickets/<int:pk>/status/", api.api_ticket_update, name="api-ticket-update"),
    path(
        "api/tickets/<int:pk>/operational-incident/",
        api.api_ticket_promote_incident,
        name="api-ticket-promote-incident",
    ),
    path("api/v1/cases/", api.api_case_upsert, name="api-v1-case-upsert"),
    path("api/v1/cases/<int:pk>/", api.api_case_detail, name="api-v1-case-detail"),
    path("api/v1/cases/<int:pk>/notes/", api.api_case_note, name="api-v1-case-note"),
    path("api/v1/cases/<int:pk>/events/", api.api_case_event, name="api-v1-case-event"),
    path(
        "api/v1/cases/external/<slug:provider>/<path:external_id>/",
        api.api_case_external_detail,
        name="api-v1-case-external-detail",
    ),
    path("preferences/", views.notification_preferences, name="notification-preferences"),
    path("knowledge-base/", views.knowledge_base_list, name="knowledge-base-list"),
    path("knowledge-base/new/", views.knowledge_base_create, name="knowledge-base-create"),
    path("knowledge-base/<slug:slug>/", views.knowledge_base_detail, name="knowledge-base-detail"),
    path("operator/board/", views.ticket_board, name="ticket-board"),
    path("operator/board/reorder/", views.reorder_ticket_board, name="ticket-board-reorder"),
    path("tickets/new/", views.ticket_create, name="ticket-create"),
    path("tickets/<int:pk>/", views.ticket_detail, name="ticket-detail"),
    path("tickets/<int:pk>/messages/", views.add_message, name="ticket-add-message"),
    path("tickets/<int:pk>/attachments/", views.add_attachment, name="ticket-add-attachment"),
    path("operator/tickets/<int:pk>/knowledge-base/", views.link_knowledge_base_article, name="ticket-link-knowledge-base"),
    path(
        "operator/tickets/<int:pk>/knowledge-base/draft/",
        views.draft_knowledge_base_from_ticket,
        name="ticket-draft-knowledge-base",
    ),
    path("operator/tickets/<int:pk>/workflow/", views.update_workflow_checklist, name="ticket-update-workflow"),
    path("operator/tickets/<int:pk>/", views.operator_update, name="operator-update"),
    path(
        "operator/tickets/<int:pk>/operational-incident/",
        views.create_operational_incident,
        name="ticket-create-operational-incident",
    ),
    path("attachments/<int:pk>/download/", views.download_attachment, name="attachment-download"),
]

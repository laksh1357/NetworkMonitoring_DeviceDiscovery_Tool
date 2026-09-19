# Monitoring API Specification

This document outlines the REST API for the new modular architecture of the LAN Watchtower system. It provides JSON endpoints for fetching devices, historical timelines, anomalies, and network topology.

## OpenAPI 3.0 Specification

```yaml
openapi: 3.0.0
info:
  title: LAN Watchtower API
  description: REST API for Network Monitoring and Device Discovery
  version: 2.0.0
servers:
  - url: http://localhost:8000/api
    description: Local Monitoring Server

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    Device:
      type: object
      properties:
        uuid:
          type: string
          format: uuid
        primary_ip:
          type: string
        primary_mac:
          type: string
        hostname:
          type: string
        vendor:
          type: string
        status:
          type: string
          enum: [Online, Offline]
        first_seen:
          type: number
          format: float
        last_seen:
          type: number
          format: float

    Error:
      type: object
      properties:
        error:
          type: string
        code:
          type: integer

security:
  - bearerAuth: []

paths:
  /devices:
    get:
      summary: List persistent devices
      description: Returns a paginated list of all known device identities.
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            default: 50
        - name: offset
          in: query
          schema:
            type: integer
            default: 0
        - name: status
          in: query
          schema:
            type: string
            enum: [Online, Offline]
      responses:
        '200':
          description: A JSON array of devices
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Device'
        '401':
          description: Unauthorized

  /devices/{id}:
    get:
      summary: Get device details
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Device object
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Device'
        '404':
          description: Device not found

  /devices/{id}/timeline:
    get:
      summary: Get device evidence timeline
      description: Returns a chronological history of device changes and events.
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Array of timeline events
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    timestamp:
                      type: number
                    event_type:
                      type: string
                    delta_summary:
                      type: object

  /devices/{id}/anomalies:
    get:
      summary: Get device anomalies
      description: Returns all anomalies detected for this specific device.
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Array of anomaly events

  /events:
    get:
      summary: List network-wide correlated events
      parameters:
        - name: severity
          in: query
          schema:
            type: string
            enum: [INFORMATIONAL, LOW, MEDIUM, HIGH]
      responses:
        '200':
          description: Array of correlated events

  /network/topology:
    get:
      summary: Get network topology graph
      description: Returns nodes and edges representing the network layout.
      responses:
        '200':
          description: Graph object (nodes and edges)
          content:
            application/json:
              schema:
                type: object
                properties:
                  nodes:
                    type: array
                    items:
                      type: object
                  edges:
                    type: array
                    items:
                      type: object

  /network/statistics:
    get:
      summary: Get network-wide statistics
      description: Returns high-level metrics (total devices, active alerts, discovery status).
      responses:
        '200':
          description: Statistics object

  /system/status:
    get:
      summary: Get system health
      description: Returns memory usage, database size, and discovery engine status.
      responses:
        '200':
          description: System status
```

## Security & Implementation Notes
- **Request Validation:** All incoming query parameters (like `limit`, `offset`) and path UUIDs must be validated before querying the DB.
- **Pagination:** Essential for `/devices` and `/events` to prevent massive JSON payloads crashing the UI.
- **Error Handling:** Centralized exception handlers catch 404s (Not Found) and 400s (Bad Request) to return structured JSON `{"error": "message"}` instead of HTML stack traces.
- **Rate Limiting:** IP-based token-bucket rate limits must be applied, especially on intensive routes like `/network/topology` or `/devices/{id}/timeline`.

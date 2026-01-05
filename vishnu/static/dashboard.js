/**
 * Dashboard JavaScript for real-time updates
 * Handles WebSocket/SSE connections and event processing
 */

class DashboardClient {
    constructor() {
        this.eventSource = null;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }

    connect() {
        // Try WebSocket first, fallback to polling
        this.startPolling();
    }

    startPolling() {
        // Poll for new events every 2 seconds
        setInterval(() => {
            this.fetchRecentEvents();
        }, 2000);
    }

    async fetchRecentEvents() {
        try {
            const response = await fetch('/api/action-history?limit=5');
            const data = await response.json();
            
            // Process new events
            if (data.history && data.history.length > 0) {
                // Update UI with new events
                this.updateUI(data);
            }
        } catch (error) {
            console.error('Error fetching events:', error);
        }
    }

    updateUI(data) {
        // Update statistics, blocked IPs, etc.
        // This would be called by the main dashboard code
    }

    disconnect() {
        if (this.eventSource) {
            this.eventSource.close();
        }
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Initialize dashboard client
const dashboardClient = new DashboardClient();
dashboardClient.connect();


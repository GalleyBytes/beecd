import axios from 'axios';

// Custom event for auth-required navigation (avoids hard page reload)
export const AUTH_REDIRECT_EVENT = 'auth:redirect-to-login';

// Create axios instance with default config
export const apiClient = axios.create({
    baseURL: '/api',
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Response interceptor for error handling
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            // Only redirect if not already on login page
            if (window.location.pathname !== '/login') {
                // Dispatch custom event for React to handle navigation
                window.dispatchEvent(new CustomEvent(AUTH_REDIRECT_EVENT));
            }
        }
        return Promise.reject(error);
    }
);

export default apiClient;

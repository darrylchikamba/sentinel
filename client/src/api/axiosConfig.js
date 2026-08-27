import axios from 'axios'

const apiUrl = import.meta.env.VITE_API_URL?.trim()

if (!apiUrl) {
  console.error(
    'SENTINEL configuration error: VITE_API_URL is missing or empty. ' +
      'API requests cannot be routed reliably.',
  )
}

const api = axios.create({
  baseURL: apiUrl,
})

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sentinel_token')

    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }

    return config
  },
  (error) => Promise.reject(error),
)

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('sentinel_token')
      localStorage.removeItem('sentinel_user')

      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login'
      }
    }

    return Promise.reject(error)
  },
)

export default api

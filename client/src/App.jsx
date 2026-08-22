import { Navigate, Route, Routes } from 'react-router-dom'
import AppLayout from './components/AppLayout'
import ProtectedRoute from './components/ProtectedRoute'
import Analysis from './pages/Analysis'
import Dashboard from './pages/Dashboard'
import Graph from './pages/Graph'
import History from './pages/History'
import IncidentView from './pages/IncidentView'
import Login from './pages/Login'
import Register from './pages/Register'
import Upload from './pages/Upload'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/analysis/:investigationId" element={<Analysis />} />
        <Route path="/graph/:investigationId" element={<Graph />} />
        <Route path="/incident/:investigationId" element={<IncidentView />} />
        <Route path="/history" element={<History />} />
      </Route>

      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  )
}

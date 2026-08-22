import { Outlet } from 'react-router-dom'
import Navbar from './Navbar'

export default function AppLayout() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#F4F4F0',
      }}
    >
      <Navbar />
      <main
        style={{
          minHeight: '100vh',
          marginLeft: '220px',
          padding: '32px',
        }}
      >
        <Outlet />
      </main>
    </div>
  )
}

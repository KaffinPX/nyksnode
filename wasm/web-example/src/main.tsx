import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import init, { initThreadPool } from '../../pkg/nyks_wasm'

await init()
await initThreadPool(4)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
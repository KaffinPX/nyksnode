import { useState } from 'react'
import { benchmark_nop_generation } from '../../pkg/nyks_wasm'

function App() {
  const [ status, setStatus ] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')
  const [ durationMs, setDurationMs ] = useState<number | null>(null)

  function handleProve() {
    setStatus('loading')

    try {
      const start = performance.now()
      benchmark_nop_generation() // note: freezes web page
      const end = performance.now()

      setDurationMs(end - start)
      setStatus('done')
    } catch (err) {
      console.error(err)
      setStatus('error')
    }
  }

  return (
    <>
      <button onClick={handleProve} disabled={status === 'loading'}>
        {status === 'loading' ? 'Proving…' : 'prove nop proofcollection'}
      </button>
      {status === 'done' && durationMs !== null && (
        <p>Benchmark: {durationMs.toFixed(2)} ms</p>
      )}
      {status === 'error' && <p>Something went wrong - check console.</p>}
    </>
  )
}

export default App
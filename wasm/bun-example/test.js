import init, { initThreadPool, WalletEntropy, benchmark_lock_script_proving, benchmark_nop_generation } from "..//pkg"

await init()
await initThreadPool(4)

const wallet = new WalletEntropy("welcome ask impact scrub betray modify spatial saddle broken hybrid goddess follow grief false near pulp wife glove")
const specialAddress = wallet.nthSymmetricAddress(1n)

console.log("Imported wallet!")
console.log(specialAddress)

console.time("benchmark")
benchmark_lock_script_proving()
console.timeEnd("benchmark")

console.time("benchmark2")
benchmark_nop_generation()
console.timeEnd("benchmark2")
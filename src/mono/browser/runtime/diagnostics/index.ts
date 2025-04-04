// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

import type { GlobalObjects } from "../types/internal";
import type { CharPtr, VoidPtr } from "../types/emscripten";

import { diagnosticHelpers, setRuntimeGlobalsImpl } from "./globals";

/* eslint-disable @typescript-eslint/no-unused-vars */
export function setRuntimeGlobals (globalObjects: GlobalObjects): void {
    setRuntimeGlobalsImpl(globalObjects);

    diagnosticHelpers.ds_rt_websocket_create = (urlPtr :CharPtr):number => {
        // Not implemented yet
        return 1;
    };

    diagnosticHelpers.ds_rt_websocket_send = (client_socket :number, buffer:VoidPtr, bytes_to_write:number):number => {
        // Not implemented yet
        return bytes_to_write;
    };

    diagnosticHelpers.ds_rt_websocket_poll = (client_socket :number):number => {
        // Not implemented yet
        return 0;
    };

    diagnosticHelpers.ds_rt_websocket_recv = (client_socket :number, buffer:VoidPtr, bytes_to_read:number):number => {
        // Not implemented yet
        return 0;
    };

    diagnosticHelpers.ds_rt_websocket_close = (client_socket :number):number => {
        // Not implemented yet
        return 0;
    };
}

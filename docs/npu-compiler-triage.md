<!-- SPDX-License-Identifier: Apache-2.0 -->
# NPU dynamic-reshape compiler crash

Investigation date: September 19, 2026. Tracks [issue #20](https://github.com/archledger/intel-npu-stack/issues/20).
Upstream report: [openvinotoolkit/npu_compiler#352](https://github.com/openvinotoolkit/npu_compiler/issues/352).

## Findings

The original, unbounded-batch graphs still crash during NPU compilation. The
failure has been reduced to an application-neutral six-node graph with 24 bytes
of integer constants: a parameter, reduction axes, `ReduceMean`, a reshape
pattern, `Reshape`, and a result. No trained weights or inference inputs are
required.

The backtrace from both the original graph and this tiny IR reaches:

```text
mlir::RankedTensorType::getEncoding()
vpux::getTensorAttr(mlir::RankedTensorType)
vpux::Core::BoundedTensorType::getBounds()
vpux::IE::NGraphImporter::parseNode(... ov::op::v1::Reshape ...)
```

The pinned compiler source calls `getBounds()` on the result of an unchecked
`mlir::dyn_cast<Core::BoundedTensorType>` in the dynamic `Reshape` importer:

```cpp
const auto& inputBounds =
    mlir::dyn_cast<Core::BoundedTensorType>(inputs[0].getType()).getBounds();
```

See [the pinned source](https://github.com/openvinotoolkit/npu_compiler/blob/6a7a7c531f54baed1dddfda1b80299413c4c6943/src/vpux_compiler/src/frontend/IE.cpp#L2079).
The same statement is present in upstream commit
`0b38f7d42113ff329ac2bdd33583d123de4ccf2f`; that newer compiler was inspected as
source, not tested as a binary. The retained build's change to this source file
only removes a stale `TransposeFQ` pass-disable call. The tiny reproducer has no
fake-quantization nodes.

## Reproduce and compare controls

The standalone source is
[`scripts/reproducers/npu-reshape-bounds.cpp`](../scripts/reproducers/npu-reshape-bounds.cpp).
Build it against the SDK headers matching the runtime being investigated:

```sh
: "${OPENVINO_INCLUDE_DIR:?Set the matching SDK include directory}"
: "${OPENVINO_RUNTIME_LIBRARY:?Set the full matching runtime library path}"
c++ -std=c++17 -O1 -g -isystem "$OPENVINO_INCLUDE_DIR" \
  scripts/reproducers/npu-reshape-bounds.cpp "$OPENVINO_RUNTIME_LIBRARY" \
  -o npu-reshape-bounds

./npu-reshape-bounds static CPU
./npu-reshape-bounds static NPU
./npu-reshape-bounds bounded NPU
./npu-reshape-bounds unbounded CPU
./npu-reshape-bounds unbounded NPU
```

Run each case as a separate normal-user process. An optional output prefix
serializes the graph to IR XML and BIN files and refuses existing paths.

Observed on the source-built OpenVINO/compiler 2026.2.0-2, compiler source
`6a7a7c5` (`npu_ud_2026_28_rc1`), driver/firmware 1.38.0, Level Zero 1.32.0,
Fedora 44 kernel 7.2.5, NPU `8086:643e`:

| Input batch | CPU compilation | NPU compilation |
|---|---|---|
| Static `1` | 3/3 pass | 3/3 pass |
| Bounded `1..4` | 3/3 pass | 3/3 reported errors in `ConvertReduceToPooling`; no SIGSEGV |
| Unbounded `?` | 3/3 pass | 3/3 SIGSEGV in the stack above |

The bounded case avoids this crash but is not a working workaround for this
graph. The compiler should diagnose an unsupported shape without terminating
the calling process. No compiler-library patch has been deployed by this
investigation.

The earlier intermittent static BlazeFace observation came from the research
harness with the ABI error described below. It remains unconfirmed independently
of that harness. The matched-stack compile-only retest passed three attempts,
which does not establish that every source of intermittent failure is resolved.

## Validated static-shape workaround

All four original crashers compile on NPU after explicitly fixing batch to 1
before compilation. This was verified independently through the C++ and C APIs:

| Graph | Imported input | Tested static input |
|---|---|---|
| glintr100 | `[?,3,112,112]` | `[1,3,112,112]` |
| liveness_vit | `[?,3,224,224]` | `[1,3,224,224]` |
| face_landmark | `[?,256,256,3]` | `[1,256,256,3]` |
| TFLite mesh | `[?,256,256,3]` | `[1,256,256,3]` |

The caller must choose a shape that matches its actual input contract. This is
compile-only evidence; it does not establish inference parity, performance, or
application readiness.

### Correction to the earlier reshape diagnosis

The earlier standalone research harness declared the C ABI partial-shape rank
as one integer. The SDK defines `ov_rank_t` as an `ov_dimension_t` interval
containing `min` and `max`. On this x86_64 build, `ov_partial_shape_t` is 24 bytes
with a 16-byte rank, while the hand-written research declaration was 16 bytes.
Passing that structure by value used the wrong ABI.

Consequently, the earlier claim that these inputs were unranked or could not be
reshaped is invalid. All four have known rank 4 and a dynamic batch dimension.
The product's native probes use the C++ SDK and do not contain this declaration.

Use the SDK's declared types and constructors. The verified C sequence is:

```c
const int64_t dims[] = {1, 3, 112, 112}; /* Example caller-selected input. */
ov_partial_shape_t shape = {0};
ov_status_e status = ov_partial_shape_create_static(4, dims, &shape);
if (status == OK) {
    status = ov_model_reshape_single_input(model, shape);
}
ov_partial_shape_free(&shape);
/* Compile on NPU only after checking status == OK. */
```

The unchecked compiler type cast remains an upstream defect. The static-shape
workaround corrects the input contract; it does not turn a crashing unsupported
graph into valid dynamic-shape support.

<!-- SPDX-License-Identifier: Apache-2.0 -->
# NPU dynamic-reshape compiler crash

Investigation date: September 19, 2026; batch-layout route verified September 26, 2026. Tracks
[issue #20](https://github.com/archledger/intel-npu-stack/issues/20).
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
The same statement is present in upstream tag `npu_ud_2026_38_rc1` and
commit `0b38f7d42113ff329ac2bdd33583d123de4ccf2f`, where it moved to line 2203;
that newer compiler was inspected as source, not tested as a binary. The
retained build's change to this source file only removes a stale `TransposeFQ`
pass-disable call. The tiny reproducer has no fake-quantization nodes.

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
./npu-reshape-bounds bounded-layout NPU
./npu-reshape-bounds unbounded-layout NPU
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

Without a batch layout, the bounded case avoids this crash but does not
compile this graph. The compiler should diagnose an unsupported shape without
terminating the calling process. No compiler-library patch has been deployed by
this investigation.

The earlier intermittent static BlazeFace observation came from the research
harness with the ABI error described below. It remains unconfirmed independently
of that harness. The matched-stack compile-only retest passed three attempts,
which does not establish that every source of intermittent failure is resolved.

## Batch-layout route

Declaring the batch dimension in the input layout avoids the crash and keeps
the batch dynamic. The OpenVINO NPU plugin then reshapes the model to batch 1
before compilation and runs each batch item separately at inference time:

```cpp
for (const auto& input : model->get_parameters()) {
    input->set_layout(ov::Layout("N..."));  // the batch is dimension 0
}
auto compiled = core.compile_model(model, "NPU");
```

In OpenVINO 2026.2.0 the plugin takes this path only when dimension 0 is the
only dynamic dimension of every input and output and the tensors have names
(`src/plugins/intel_npu/src/plugin/src/transformations.cpp`). Models imported
from ONNX or TFLite have names. Without a batch layout, `ov::get_batch` fails,
the plugin leaves batching to the compiler, and the unbounded graph reaches
the importer above. The reproducer's `-layout` modes name the tensors, set the
`N...` layout, print both and run one inference with a batch of 3. The native
CI job builds the reproducer against its pinned SDK and runs every mode on CPU
(`native/tests/reproducer_test.py`); the NPU cases remain hardware runs.

Observed on the same packages on kernel 7.2.7, September 26, with
deterministic synthetic inputs:

| Graph | Without a batch layout | With the `N...` layout |
|---|---|---|
| Reproducer, unbounded `?` | SIGSEGV | Compiles; batch 3 gives `[3,1]` = 2, 0, 1 |
| Reproducer, bounded `1..4` | Reported compiler error | Compiles; batch 3 gives `[3,1]` = 2, 0, 1 |
| glintr100 `[?,3,112,112]` | SIGSEGV | Compiles and runs batches 1 and 2 |
| liveness_vit `[?,3,224,224]` | SIGSEGV | Compiles and runs batches 1 and 2 |
| face_landmark `[?,256,256,3]` | SIGSEGV | Compiles and runs batches 1 and 2 |
| TFLite mesh `[?,256,256,3]` | SIGSEGV | Compiles and runs batches 1 and 2 |

The compiled models keep a dynamic batch. A batch of 2 gave exactly the
outputs of two batch-1 runs, and NPU outputs differed from CPU by at most
0.0035 for glintr100 (outputs up to 1.58), 0.0007 for liveness_vit (up to
0.054) and 0.37 for both mesh models (up to 220). This is compilation and
consistency evidence; it does not establish accuracy for any application.

## Validated static-shape workaround

Fixing the batch to 1 before compilation also avoids the crash, but the
compiled model then accepts only that batch. All four original crashers
compile on NPU after explicitly fixing batch to 1 before compilation. This was
verified independently through the C++ and C APIs:

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

The unchecked compiler type cast remains an upstream defect. An unbounded
graph that reaches the compiler without a batch layout still terminates the
calling process instead of returning an error. The batch layout and the static
shape avoid that path; they do not change the compiler.

import os
import pickle
import numpy as np
import onnx
from onnx import helper, TensorProto


def create_base_onnx(weights, bias, filename):
    # Ensure directory exists
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Create input and output value infos
    input_info = helper.make_tensor_value_info(
        'input',
        TensorProto.FLOAT,
        [1, 32]
    )

    output_info = helper.make_tensor_value_info(
        'output',
        TensorProto.FLOAT,
        [1, 32]
    )

    # Create weight and bias initializers
    weight_tensor = helper.make_tensor(
        name='fc1.weight',
        data_type=TensorProto.FLOAT,
        dims=[32, 32],
        vals=weights.flatten().tolist()
    )

    bias_tensor = helper.make_tensor(
        name='fc1.bias',
        data_type=TensorProto.FLOAT,
        dims=[32],
        vals=bias.flatten().tolist()
    )

    # Create network nodes (MatMul followed by Add)
    matmul_node = helper.make_node(
        'MatMul',
        inputs=['input', 'fc1.weight'],
        outputs=['matmul_out']
    )

    add_node = helper.make_node(
        'Add',
        inputs=['matmul_out', 'fc1.bias'],
        outputs=['output']
    )

    # Create graph structure
    graph = helper.make_graph(
        nodes=[matmul_node, add_node],
        name='safe_test_network',
        inputs=[input_info],
        outputs=[output_info],
        initializer=[weight_tensor, bias_tensor]
    )

    # Create and save model using ONNX opset 26
    model = helper.make_model(
        graph,
        producer_name='model-security-scanner-mvp',
        opset_imports=[helper.make_opsetid('', 26)]
    )

    onnx.save(model, filename)
    print(f"Generated ONNX model: {filename}")


def generate_clean_model(filepath):
    # Normally distributed weights
    np.random.seed(42)

    weights = np.random.normal(
        0,
        0.1,
        size=(32, 32)
    ).astype(np.float32)

    bias = np.random.normal(
        0,
        0.05,
        size=(32,)
    ).astype(np.float32)

    create_base_onnx(weights, bias, filepath)


def generate_stego_model(
    filepath,
    secret_text="STEGO_DEMO_MARKER_2026"
):
    np.random.seed(42)

    weights = np.random.normal(
        0,
        0.1,
        size=(32, 32)
    ).astype(np.float32)

    bias = np.random.normal(
        0,
        0.05,
        size=(32,)
    ).astype(np.float32)

    # Convert text to binary bitstream
    bits = []

    for char in secret_text:
        byte = ord(char)

        for i in range(8):
            bits.append((byte >> i) & 1)

    # Flatten weights and cast to uint32
    # so we can modify the least significant bits
    flat_weights = weights.flatten()
    flat_weights_uint = flat_weights.view(np.uint32)

    # Embed bits into least significant bit (LSB)
    # of weight float values
    for idx, bit in enumerate(bits):
        if idx >= len(flat_weights_uint):
            break

        # Clear the lowest bit and set the secret bit
        flat_weights_uint[idx] = (
            (flat_weights_uint[idx] & 0xFFFFFFFE) | bit
        )

    # View back as float32
    embedded_weights = (
        flat_weights_uint
        .view(np.float32)
        .reshape((32, 32))
    )

    create_base_onnx(
        embedded_weights,
        bias,
        filepath
    )


def generate_anomalous_model(filepath):
    np.random.seed(42)

    weights = np.random.normal(
        0,
        0.1,
        size=(32, 32)
    ).astype(np.float32)

    bias = np.random.normal(
        0,
        0.05,
        size=(32,)
    ).astype(np.float32)

    # Insert outliers and extreme statistical anomalies
    weights[0, 0] = np.nan
    weights[0, 1] = np.inf
    weights[0, 2] = -np.inf

    weights[5, 5] = 1.2e12
    weights[10, 10] = -8.5e11

    create_base_onnx(
        weights,
        bias,
        filepath
    )


def generate_unsafe_pickle_model(filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    # Harmless class that triggers a built-in print call
    # during simulated load
    class HarmlessDemoExploit:
        def __reduce__(self):
            import builtins

            return (
                builtins.print,
                (
                    "[SECURITY RUNTIME WARNING] "
                    "Safe Pickle Execution Intercepted!",
                )
            )

    with open(filepath, 'wb') as f:
        pickle.dump(HarmlessDemoExploit(), f)

    print(
        f"Generated safe unsafe-pickle test fixture: {filepath}"
    )


if __name__ == '__main__':
    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    generate_clean_model(
        os.path.join(
            base_dir,
            "clean_model.onnx"
        )
    )

    generate_stego_model(
        os.path.join(
            base_dir,
            "stego_model.onnx"
        )
    )

    generate_anomalous_model(
        os.path.join(
            base_dir,
            "anomalous_model.onnx"
        )
    )

    generate_unsafe_pickle_model(
        os.path.join(
            base_dir,
            "unsafe_pickle.pth"
        )
    )
//! The ONNX Runtime session: loading the graph and running one window.

use std::path::Path;

use ort::session::Session;
use ort::value::Tensor;

use crate::schema::Encoded;
use crate::Error;

/// What the graph returns for one window.
pub(crate) struct Output {
    /// Shape of `probs`: `[fields, words, width]`.
    pub(crate) shape: Vec<i64>,
    pub(crate) probs: Vec<f32>,
    pub(crate) counts: Vec<f32>,
}

pub(crate) struct Runner {
    session: Session,
}

impl Runner {
    pub(crate) fn load(model: &Path) -> Result<Self, Error> {
        let session = Session::builder()
            .and_then(|builder| builder.commit_from_file(model))
            .map_err(|error| Error::Model(error.to_string()))?;
        Ok(Self { session })
    }

    pub(crate) fn run(&self, encoded: &Encoded) -> Result<Output, Error> {
        let seq = encoded.input_ids.len();
        let words = encoded.word_first.len();
        let slots = encoded.schema_special.len();
        let input_ids = tensor(seq, encoded.input_ids.clone())?;
        let attention_mask = tensor(seq, vec![1i64; seq])?;
        let word_indices = tensor(words, encoded.word_first.clone())?;
        let schema_indices = tensor(slots, encoded.schema_special.clone())?;
        let inputs = ort::inputs! {
            "input_ids" => input_ids,
            "attention_mask" => attention_mask,
            "text_word_indices" => word_indices,
            "schema_special_indices" => schema_indices,
        }
        .map_err(|error| Error::Inference(error.to_string()))?;
        let outputs = self
            .session
            .run(inputs)
            .map_err(|error| Error::Inference(error.to_string()))?;

        let (shape, probs) = outputs["span_probs"]
            .try_extract_raw_tensor::<f32>()
            .map_err(|error| Error::Inference(error.to_string()))?;
        let (_, counts) = outputs["count_logits"]
            .try_extract_raw_tensor::<f32>()
            .map_err(|error| Error::Inference(error.to_string()))?;
        Ok(Output {
            shape: shape.to_vec(),
            probs: probs.to_vec(),
            counts: counts.to_vec(),
        })
    }
}

/// A `[1, len]` int64 tensor: the batch is always one window.
fn tensor(len: usize, values: Vec<i64>) -> Result<Tensor<i64>, Error> {
    Tensor::from_array(([1, len], values)).map_err(|error| Error::Inference(error.to_string()))
}

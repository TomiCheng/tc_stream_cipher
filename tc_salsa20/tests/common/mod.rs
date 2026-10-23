pub fn unhex(value: &str) -> Vec<u8> {
    let value: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum OracleState {
    Round1Ongoing,
    Round1Completed,
    Round2Ongoing,
    Round2Completed,
    Completed,
}

#[derive(Debug)]
pub enum AVError {
    WrongPosition(String),
    WrongMsg(String),
    WrongState(String),
    MsgAlreadySent(usize),
}

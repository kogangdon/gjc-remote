export async function dispatchAuthorizedInteraction({
  interaction,
  authorization,
  onButton,
  onChatInput,
}) {
  if (interaction.isButton()) {
    if (!authorization.isAuthorized(interaction.user.id)) {
      await interaction
        .reply({
          content: "You are not authorized to view GJC tool logs.",
          ephemeral: true,
        })
        .catch(() => {});
      return "denied";
    }

    try {
      await onButton(interaction);
      return "handled";
    } catch (error) {
      console.error(
        "Discord button interaction handler failed:",
        error instanceof Error ? error.message : String(error)
      );
      return "failed";
    }
  }

  if (!interaction.isChatInputCommand()) return "ignored";
  if (!authorization.isAuthorized(interaction.user.id)) {
    await interaction
      .reply({
        content: "You are not authorized to run GJC commands.",
        ephemeral: true,
      })
      .catch(() => {});
    return "denied";
  }

  try {
    await onChatInput(interaction);
    return "handled";
  } catch (error) {
    console.error(
      "Discord chat-input interaction handler failed:",
      error instanceof Error ? error.message : String(error)
    );
    return "failed";
  }
}

export async function dispatchAuthorizedMessage({ message, authorization, onMessage }) {
  if (message.author.bot || !message.guildId) return "ignored";
  if (!authorization.isAuthorized(message.author.id)) return "denied";

  await onMessage(message);
  return "handled";
}

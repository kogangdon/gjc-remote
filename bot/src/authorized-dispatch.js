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

    await onButton(interaction);
    return "handled";
  }

  if (!interaction.isChatInputCommand()) return "ignored";
  if (!authorization.isAuthorized(interaction.user.id)) {
    await interaction.reply({
      content: "You are not authorized to run GJC commands.",
      ephemeral: true,
    });
    return "denied";
  }

  await onChatInput(interaction);
  return "handled";
}

export async function dispatchAuthorizedMessage({ message, authorization, onMessage }) {
  if (message.author.bot || !message.guildId) return "ignored";
  if (!authorization.isAuthorized(message.author.id)) return "denied";

  await onMessage(message);
  return "handled";
}
